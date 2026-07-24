const PROTOCOL_VERSION = 2;
const RUN_LIFETIME_MS = 6 * 60 * 60 * 1000;
const encoder = new TextEncoder();
const SCORE_RECOVERIES = [
  {
    id: "recovery:matthew:211646:2026-07-24",
    name: "MATTHEW",
    score: 211646,
    level: 19,
    cores: 300,
    date: "2026-07-24T03:37:01.000Z",
  },
];

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...extraHeaders,
    },
  });
}

function apiError(status, code, message) {
  return json({ ok: false, error: code, message }, status);
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeBase64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(
    Math.ceil(value.length / 4) * 4,
    "=",
  );
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function randomToken(bytes = 18) {
  return base64url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function cleanName(value) {
  return String(value || "")
    .replace(/[^a-z0-9 _-]/gi, "")
    .trim()
    .slice(0, 12)
    .toUpperCase();
}

function cleanInteger(value, minimum, maximum) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum)
    return null;
  return parsed;
}

function usesLegacyBossCadence(version) {
  const match = String(version || "").match(/^v?(\d+)\.(\d+)\.(\d+)/i);
  if (!match) return false;
  const [, major, minor, patch] = match.map(Number);
  return major === 1 && minor === 0 && patch <= 1;
}

function sortScores(scores) {
  return scores
    .sort(
      (left, right) =>
        right.score - left.score ||
        right.level - left.level ||
        left.date.localeCompare(right.date),
    )
    .slice(0, 50);
}

async function fingerprintRequest(request) {
  const ip = String(request.headers.get("cf-connecting-ip") || "local").slice(
      0,
      64,
    ),
    agent = String(request.headers.get("user-agent") || "unknown").slice(
      0,
      180,
    ),
    digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(`${ip}\n${agent}`),
    );
  return base64url(new Uint8Array(digest));
}

function withPublicHeaders(response, request) {
  const headers = new Headers(response.headers);
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-methods", "GET, POST, OPTIONS");
  headers.set("access-control-allow-headers", "content-type");
  headers.set("access-control-max-age", "86400");
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "no-referrer");
  headers.set("permissions-policy", "interest-cohort=()");
  headers.set("cross-origin-resource-policy", "cross-origin");
  if (request.method !== "GET") headers.set("cache-control", "no-store");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export class LeaderboardStore {
  constructor(context) {
    this.context = context;
    this.storage = context.storage;
    this.signingKeyPromise = null;
    this.rateWindows = new Map();
  }

  async signingKey() {
    if (!this.signingKeyPromise) {
      this.signingKeyPromise = (async () => {
        let encoded = await this.storage.get("security:ticket-secret");
        if (!encoded) {
          encoded = randomToken(32);
          await this.storage.put("security:ticket-secret", encoded);
        }
        return crypto.subtle.importKey(
          "raw",
          decodeBase64url(encoded),
          { name: "HMAC", hash: "SHA-256" },
          false,
          ["sign", "verify"],
        );
      })();
    }
    return this.signingKeyPromise;
  }

  async issueTicket(run) {
    const payload = base64url(
        encoder.encode(
          JSON.stringify({
            version: 1,
            runId: run.id,
            sequence: run.sequence,
            fingerprint: run.fingerprint,
            expiresAt: run.createdAt + RUN_LIFETIME_MS,
            nonce: randomToken(9),
          }),
        ),
      ),
      signature = await crypto.subtle.sign(
        "HMAC",
        await this.signingKey(),
        encoder.encode(payload),
      );
    return `${payload}.${base64url(new Uint8Array(signature))}`;
  }

  async readTicket(value) {
    if (typeof value !== "string" || value.length > 900) return null;
    const parts = value.split(".");
    if (parts.length !== 2) return null;
    try {
      const valid = await crypto.subtle.verify(
        "HMAC",
        await this.signingKey(),
        decodeBase64url(parts[1]),
        encoder.encode(parts[0]),
      );
      if (!valid) return null;
      const payload = JSON.parse(
        new TextDecoder().decode(decodeBase64url(parts[0])),
      );
      if (
        payload.version !== 1 ||
        typeof payload.runId !== "string" ||
        typeof payload.fingerprint !== "string" ||
        !Number.isInteger(payload.sequence) ||
        !Number.isFinite(payload.expiresAt) ||
        Date.now() > payload.expiresAt
      )
        return null;
      return payload;
    } catch {
      return null;
    }
  }

  allowRequest(kind, fingerprint, limit, periodMs) {
    const now = Date.now(),
      key = `${kind}:${fingerprint}`,
      cutoff = now - periodMs,
      current = (this.rateWindows.get(key) || []).filter(
        (stamp) => stamp > cutoff,
      );
    if (current.length >= limit) {
      this.rateWindows.set(key, current);
      return false;
    }
    current.push(now);
    this.rateWindows.set(key, current);
    if (this.rateWindows.size > 2000) {
      for (const [candidate, stamps] of this.rateWindows) {
        if (!stamps.some((stamp) => stamp > now - 60_000))
          this.rateWindows.delete(candidate);
      }
    }
    return true;
  }

  async body(request) {
    const length = Number(request.headers.get("content-length") || 0);
    if (length > 24_000) throw new Error("payload_too_large");
    return request.json();
  }

  async leaderboard() {
    await this.applyScoreRecoveries();
    const scores = (await this.storage.get("leaderboard:scores")) || [];
    return scores.slice(0, 10).map((row, index) => ({
      rank: index + 1,
      name: row.name,
      score: row.score,
      level: row.level,
      cores: row.cores,
      date: row.date,
      verified: true,
    }));
  }

  async applyScoreRecoveries() {
    const migrationKey = "migration:score-recoveries:2026-07-24";
    if (await this.storage.get(migrationKey)) return;
    const existing = (await this.storage.get("leaderboard:scores")) || [],
      recovered = SCORE_RECOVERIES.filter(
        (row) => !existing.some((candidate) => candidate.id === row.id),
      ),
      scores = sortScores([...existing, ...recovered]);
    await this.storage.put({
      "leaderboard:scores": scores,
      [migrationKey]: true,
    });
  }

  async startRun(request, fingerprint) {
    if (!this.allowRequest("start", fingerprint, 8, 60_000))
      return apiError(429, "rate_limited", "Too many run requests. Try again shortly.");
    const body = await this.body(request);
    if (body?.protocol !== PROTOCOL_VERSION)
      return apiError(409, "protocol_mismatch", "Refresh the game to start a verified run.");
    const now = Date.now(),
      run = {
        id: crypto.randomUUID(),
        fingerprint,
        createdAt: now,
        updatedAt: now,
        sequence: 0,
        status: "active",
        score: 0,
        level: 1,
        cores: 0,
        combo: 0,
        multiplier: 1,
        bosses: 0,
        clientElapsedMs: 0,
        counts: {},
        gameVersion: String(body.gameVersion || "unknown").slice(0, 32),
      };
    await this.storage.put(`run:${run.id}`, run);
    return json({
      ok: true,
      protocol: PROTOCOL_VERSION,
      runId: run.id,
      sequence: run.sequence,
      ticket: await this.issueTicket(run),
      expiresAt: new Date(run.createdAt + RUN_LIFETIME_MS).toISOString(),
      security: {
        signedSession: true,
        replayProtection: true,
        authoritativeScoring: true,
      },
    });
  }

  scoreEvents(run, events, now) {
    if (!Array.isArray(events) || events.length > 80)
      throw new Error("invalid_events");
    const next = structuredClone(run);
    let totalUnits = 0;
    for (const event of events) {
      const type = String(event?.type || ""),
        count = cleanInteger(event?.count ?? 1, 1, 64);
      if (!count) throw new Error("invalid_event_count");
      totalUnits += count;
      if (totalUnits > 240) throw new Error("event_batch_too_large");
      next.counts[type] = (next.counts[type] || 0) + count;
      switch (type) {
        case "hurt":
          next.combo = 0;
          next.multiplier = 1;
          break;
        case "core":
          for (let index = 0; index < count; index++) {
            next.combo += 1;
            next.multiplier = Math.min(
              8,
              1 + Math.floor(next.combo / 5),
            );
            next.score += 100 * next.multiplier;
            next.cores += 1;
          }
          break;
        case "asteroid_large":
          next.score += 25 * next.multiplier * count;
          break;
        case "asteroid_fragment":
          next.score += 35 * next.multiplier * count;
          break;
        case "enemy_seeker":
          next.score += 60 * next.multiplier * count;
          break;
        case "enemy_strafer":
          next.score += 70 * next.multiplier * count;
          break;
        case "enemy_charger":
          next.score += 90 * next.multiplier * count;
          break;
        case "pulse_hit":
          next.score += 12 * next.multiplier * count;
          break;
        case "boss_shard":
          next.score += 65 * next.multiplier * count;
          break;
        case "boss_kill":
          for (let index = 0; index < count; index++) {
            next.bosses += 1;
            next.score +=
              (1800 + next.bosses * 350) * next.multiplier;
          }
          break;
        case "upgrade_cache":
          next.score += 500 * count;
          break;
        default:
          throw new Error("unknown_event");
      }
    }

    const seconds = Math.max(1, (now - next.createdAt) / 1000),
      asteroidCount =
        (next.counts.asteroid_large || 0) +
        (next.counts.asteroid_fragment || 0),
      enemyCount =
        (next.counts.enemy_seeker || 0) +
        (next.counts.enemy_strafer || 0) +
        (next.counts.enemy_charger || 0),
      expectedBosses = usesLegacyBossCadence(next.gameVersion)
        ? Math.floor(next.level / 7)
        : next.level < 7
          ? 0
          : 1 + Math.floor((next.level - 7) / 10);
    if ((next.counts.core || 0) > 12 + seconds * 2.2)
      throw new Error("implausible_core_rate");
    if (asteroidCount > 18 + seconds * 4.5)
      throw new Error("implausible_asteroid_rate");
    if (enemyCount > 14 + seconds * 3.8)
      throw new Error("implausible_enemy_rate");
    if ((next.counts.pulse_hit || 0) > 30 + seconds * 8)
      throw new Error("implausible_pulse_rate");
    if ((next.counts.boss_shard || 0) > 20 + seconds * 3.5)
      throw new Error("implausible_boss_damage");
    if (next.bosses > expectedBosses)
      throw new Error("boss_progression_mismatch");
    if ((next.counts.upgrade_cache || 0) > Math.max(0, next.level - 1))
      throw new Error("upgrade_progression_mismatch");
    if (next.score > 18_000 + seconds * 8_000 + next.level * 14_000)
      throw new Error("implausible_score_rate");
    if (!Number.isSafeInteger(next.score) || next.score < 0)
      throw new Error("invalid_score");
    return next;
  }

  async authenticatedRun(request, fingerprint) {
    const body = await this.body(request),
      ticket = await this.readTicket(body?.ticket);
    if (!ticket)
      return { response: apiError(401, "invalid_ticket", "The run ticket is invalid or expired.") };
    if (ticket.fingerprint !== fingerprint)
      return { response: apiError(401, "client_mismatch", "The run ticket belongs to another client.") };
    const run = await this.storage.get(`run:${ticket.runId}`);
    if (!run || run.fingerprint !== fingerprint)
      return { response: apiError(404, "run_not_found", "The verified run no longer exists.") };
    if (run.status !== "active")
      return { response: apiError(409, "run_closed", "This run has already been submitted.") };
    return { body, ticket, run };
  }

  async checkpoint(request, fingerprint) {
    if (!this.allowRequest("checkpoint", fingerprint, 40, 60_000))
      return apiError(429, "rate_limited", "Telemetry is arriving too quickly.");
    const auth = await this.authenticatedRun(request, fingerprint);
    if (auth.response) return auth.response;
    const { body, ticket, run } = auth,
      submittedSequence = cleanInteger(body.sequence, 0, 1_000_000);
    if (submittedSequence === null || submittedSequence !== ticket.sequence)
      return apiError(409, "sequence_mismatch", "The run sequence is invalid.");
    if (submittedSequence < run.sequence) {
      return json({
        ok: true,
        replay: true,
        runId: run.id,
        sequence: run.sequence,
        score: run.score,
        ticket: await this.issueTicket(run),
      });
    }
    if (submittedSequence > run.sequence)
      return apiError(409, "sequence_ahead", "The run sequence is ahead of the server.");

    const now = Date.now(),
      wallElapsedMs = now - run.createdAt,
      clientElapsedMs = cleanInteger(body.elapsedMs, 0, RUN_LIFETIME_MS),
      claimedLevel = cleanInteger(body.level, 1, 999),
      claimedCores = cleanInteger(body.cores, 0, 100_000);
    if (clientElapsedMs === null || claimedLevel === null || claimedCores === null)
      return apiError(400, "invalid_progress", "Run progress is malformed.");
    if (
      clientElapsedMs + 500 < run.clientElapsedMs ||
      clientElapsedMs > wallElapsedMs + 30_000
    )
      return apiError(422, "clock_mismatch", "Run timing failed validation.");
    const maximumLevel = 1 + Math.floor((wallElapsedMs / 1000 + 12) / 16);
    if (claimedLevel < run.level || claimedLevel > maximumLevel)
      return apiError(422, "wave_mismatch", "Wave progression failed validation.");

    try {
      const next = this.scoreEvents(
        { ...run, level: claimedLevel },
        body.events || [],
        now,
      );
      if (claimedCores !== next.cores)
        return apiError(422, "core_mismatch", "Core recovery failed validation.");
      next.level = claimedLevel;
      next.clientElapsedMs = clientElapsedMs;
      next.updatedAt = now;
      next.sequence += 1;
      await this.storage.put(`run:${next.id}`, next);
      return json({
        ok: true,
        runId: next.id,
        sequence: next.sequence,
        score: next.score,
        ticket: await this.issueTicket(next),
      });
    } catch (error) {
      return apiError(
        422,
        "run_rejected",
        `Run validation rejected ${String(error?.message || "the event stream")}.`,
      );
    }
  }

  async finishRun(request, fingerprint) {
    if (!this.allowRequest("finish", fingerprint, 6, 60_000))
      return apiError(429, "rate_limited", "Too many score submissions.");
    const auth = await this.authenticatedRun(request, fingerprint);
    if (auth.response) return auth.response;
    const { body, ticket, run } = auth,
      sequence = cleanInteger(body.sequence, 0, 1_000_000),
      level = cleanInteger(body.level, 1, 999),
      cores = cleanInteger(body.cores, 0, 100_000),
      pilot = cleanName(body.name),
      now = Date.now();
    if (!pilot)
      return apiError(400, "pilot_required", "Enter a pilot name first.");
    if (sequence !== run.sequence || ticket.sequence !== run.sequence)
      return apiError(409, "unsynced_run", "The final run checkpoint has not been accepted.");
    if (level !== run.level || cores !== run.cores)
      return apiError(422, "progress_mismatch", "Final run progress failed validation.");
    if (now - run.createdAt < 8_000 || run.score <= 0)
      return apiError(422, "run_too_short", "The run is not eligible for the leaderboard.");

    await this.applyScoreRecoveries();
    const finished = {
        ...run,
        status: "finished",
        updatedAt: now,
        finishedAt: now,
        pilot,
      },
      row = {
        id: run.id,
        name: pilot,
        score: run.score,
        level: run.level,
        cores: run.cores,
        date: new Date(now).toISOString(),
      },
      existing = (await this.storage.get("leaderboard:scores")) || [],
      scores = sortScores([
        ...existing.filter((candidate) => candidate.id !== run.id),
        row,
      ]);
    await this.storage.put({
      [`run:${run.id}`]: finished,
      "leaderboard:scores": scores,
    });
    return json({
      ok: true,
      accepted: row,
      leaderboard: (await this.leaderboard()).slice(0, 10),
    });
  }

  async fetch(request) {
    const url = new URL(request.url),
      fingerprint =
        request.headers.get("x-salvager-client") ||
        (await fingerprintRequest(request));
    try {
      if (
        request.method === "GET" &&
        (url.pathname === "/" || url.pathname === "/api/health")
      )
        return json({
          ok: true,
          service: "SPACE SALVAGER SECURE LEADERBOARD",
          status: "online",
          protocol: PROTOCOL_VERSION,
          endpoints: {
            leaderboard: "/api/leaderboard",
            health: "/api/health",
          },
        });
      if (request.method === "GET" && url.pathname === "/api/leaderboard")
        return json({
          ok: true,
          protocol: PROTOCOL_VERSION,
          leaderboard: await this.leaderboard(),
        });
      if (request.method === "POST" && url.pathname === "/api/runs/start")
        return this.startRun(request, fingerprint);
      if (
        request.method === "POST" &&
        url.pathname === "/api/runs/checkpoint"
      )
        return this.checkpoint(request, fingerprint);
      if (request.method === "POST" && url.pathname === "/api/runs/finish")
        return this.finishRun(request, fingerprint);
      return apiError(404, "not_found", "Leaderboard endpoint not found.");
    } catch (error) {
      if (String(error?.message) === "payload_too_large")
        return apiError(413, "payload_too_large", "Request payload is too large.");
      return apiError(400, "invalid_request", "The leaderboard request is invalid.");
    }
  }
}

export default {
  async fetch(request, environment) {
    if (request.method === "OPTIONS")
      return withPublicHeaders(new Response(null, { status: 204 }), request);
    const headers = new Headers(request.headers);
    headers.set("x-salvager-client", await fingerprintRequest(request));
    const forwarded = new Request(request, { headers }),
      id = environment.LEADERBOARD.idFromName("global"),
      response = await environment.LEADERBOARD.get(id).fetch(forwarded);
    return withPublicHeaders(response, request);
  },
};
