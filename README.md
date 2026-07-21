# Space Salvager

A neon, single-file arcade survival game. Recover drifting cores, weaponise
asteroid shards, survive escalating enemy waves, and challenge the Scrap
Warden.

## Play

Download the newest `space-salvager.html` from the
[latest release](https://github.com/Coop-Troop-47/space-salvager/releases/latest),
then open it in a modern desktop browser. The complete playable client remains
one portable HTML file with no install or build step.

## Controls

- `WASD` or arrow keys — move
- `Space` — pulse
- `C` or `Shift` — dash
- `F` or `X` — fire an unlocked shard shot
- `P` or `Escape` — pause

## Online leaderboard

The global leaderboard is backed by a Cloudflare Worker and Durable Object.
The server issues signed run tickets, reconstructs scores from typed gameplay
events, rejects replayed checkpoints, and applies timing and score plausibility
checks. Local best runs continue to work if the network is unavailable.

## Releases

The current version is **v1.0.1**. The main menu checks the public GitHub
release feed periodically and offers the new single-file build when a newer
semantic version is available.
