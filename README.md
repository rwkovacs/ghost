# ghost

An anonymous, no-account forum. No usernames, no email, no tracking cookies. Every post/comment passes a combined math + proof-of-work + honeypot + minimum-solve-time challenge.

## Positioning

This is a free-speech-leaning, anonymous discussion site. Moderation is minimal: admins can remove illegal content (CSAM, credible threats, doxxing, copyright) and ban the corresponding hashed IP. Everything else stays up.

## Stack

- Node.js + Express
- SQLite (via `better-sqlite3`)
- Server-rendered EJS
- No client-side framework

## Run it

```
npm install
ADMIN_PASSWORD=your-password IP_SALT=a-random-string CAPTCHA_SECRET=another-random-string npm start
```

Open http://localhost:3000.

First time:
1. Go to `/new-ghost` and make a "ghost" (a sub).
2. `/submit` to post to it.
3. Open `/admin`, log in with `ADMIN_PASSWORD`, to moderate.

## How the anti-bot challenge works

Every write (post, comment, create-ghost) requires solving:

1. **Math question** — `a op b` with a server-signed HMAC token (so the expected answer can't be replayed or tampered with).
2. **Proof-of-work** — client must find a nonce such that `SHA-256(challenge || nonce)` has at least 18 leading zero bits. Typically 1–5 seconds of CPU work in a browser; essentially free for one user, expensive at spam volume.
3. **Honeypot** — hidden `website` field; bots that fill every input get flagged.
4. **Minimum solve time** — reject submissions faster than 3 s from token issue.
5. **Single-use nonce** — each signed token can only be used once.
6. **Rate limiting** — 8 writes/min per IP, 60 votes/min per IP.

### Honest caveat

No captcha is truly "unsolvable by bots" in 2026. Modern vision models crack image captchas; LLMs solve text puzzles; PoW is just economics. The design goal here is to make bulk spam **expensive** (CPU-time + per-request work) and **noisy** (rate limits + honeypot + replay protection), not impossible. For higher-stakes deployments, stack this behind Cloudflare Turnstile / hCaptcha.

## Anonymity model

- No usernames, emails, or signup.
- IPs are SHA-256(salt || ip) hashed at write time. Raw IPs are never stored.
- Votes are deduped by the same IP hash.
- Bans target the IP hash. (Shared NAT / VPN exits can still round-trip; that's the tradeoff of anonymity.)

## Admin

- `/admin` with `ADMIN_PASSWORD`.
- Actions: remove/restore any post or comment, ban/unban by IP hash.

## Env vars

| var | purpose |
|---|---|
| `PORT` | default `3000` |
| `ADMIN_PASSWORD` | admin login. **set this in prod.** |
| `IP_SALT` | salt for hashing IPs. Rotate to invalidate old bans. |
| `CAPTCHA_SECRET` | HMAC key for captcha tokens. |
| `POSTER_ID_SECRET` | HMAC key for per-thread poster IDs. Rotate to reset all thread IDs. |

## Per-thread poster IDs

Within a single thread, the same hashed IP always shows the same 8-char poster ID (e.g. `#5859a988`). Across different threads, the same IP gets a different ID — so you can tell "this is the same person in this thread" without tracking them across the site. The OP's ID is tagged `OP` and highlighted.

## Country flags

Each post and comment shows the poster's country as a flag emoji + ISO code (e.g. 🇺🇸 US), looked up from the raw IP at submission time using the bundled `geoip-lite` MaxMind GeoLite database (offline, no third-party calls). The country is stored on the row, so it's stable even if the poster's IP later changes. Unknown/private IPs show 🏴 ??.

Make sure `app.set('trust proxy', N)` matches your proxy depth so `req.ip` gets the real client IP in production, otherwise every request will look like it came from the proxy.

## Submission cooldown

Every IP hash is rate-limited to **one submission (post or comment) every 2 minutes**. This is layered on top of the 8/min per-IP rate limit and the per-submission captcha/PoW.

## What it doesn't do (by design)

- No user accounts, DMs, or notifications.
- No image hosting (just link submissions).
- No federation / ActivityPub.
- Newest-first sort only — add a `hot` ranking later if you want.
