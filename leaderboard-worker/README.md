# Space Salvager secure leaderboard

Cloudflare Worker + SQLite-backed Durable Object for the global leaderboard.

Security is enforced on the server:

- server-generated HMAC run tickets;
- one-use checkpoint sequences and replay rejection;
- score reconstruction from typed gameplay events;
- wave, timing, event-rate, boss, core, and score plausibility checks;
- client fingerprint binding and per-route throttling;
- final scores are taken only from server state, never from the submit body.

The Worker can be deployed before authentication with:

```sh
npx wrangler@latest deploy --temporary
```

Claim the URL printed by Wrangler within 60 minutes to retain the Worker and
its leaderboard storage permanently.
