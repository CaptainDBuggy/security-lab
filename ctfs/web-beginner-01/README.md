# 🔐 SecureVault — Beginner Web CTF

A deliberately vulnerable web app for practicing web recon and exploitation.
Everything runs locally in Docker. **Authorized target: this box only.**

## Run it

This runs on **Docker Desktop** as a Compose project named **`securevault-ctf`**.

**Easiest — the GUI:** open Docker Desktop → **Containers** → find **securevault-ctf** →
use the ▶ / ⏹ buttons to start and stop it whenever you want. Click the container
to see logs, or the `8081:5000` port link to open it in your browser.

**Or the terminal:**

```bash
cd ~/ctf-labs/web-beginner-01
docker compose up -d          # start (builds first time)
docker compose stop           # stop (keeps it; restart later)
docker compose start          # start again
docker compose logs -f        # watch server logs
docker compose down           # remove entirely (fresh reset next 'up')
```

Open http://localhost:8081. Stopping/starting keeps your state; `down` then `up`
gives a clean reset.

## The mission

There are **3 flags** hidden in the app, in the format `FLAG{...}`.
They get progressively harder and each teaches a different core web skill:

1. **Recon** — what does the app tell you about itself if you look closely?
2. **Client-side trust** — the browser sends things to the server. Who decides what?
3. **Injection** — what happens when input becomes part of a query?

## Rules of the game (with your coach)

- Try black-box first: poke the app from the outside before reading `app.py`.
- **Ask me for a hint** anytime — I'll nudge, not spoil. Say *"hint"* for a gentle
  one, *"I'm really stuck"* for a stronger one.
- I'll ask you questions along the way. Tell me what you're seeing and what you've tried.

## Suggested toolkit

- Your browser + its **DevTools** (Network tab, Application/Storage tab)
- `curl` — inspect raw requests/responses
- Burp Suite (optional) — intercept and tamper requests

Good luck. Start at http://localhost:8081 and tell me what you notice.
