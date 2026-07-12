# 🏢 OrgHub — Intermediate Web CTF

A staff portal with **broken access control**. Everything runs locally in Docker.
**Authorized target: this box only.**

## Run it

Compose project name: **`orghub-ctf`**. Publishes on host port **8081**
(Burp keeps its default 8080, so you can proxy freely).

**Docker Desktop GUI:** Containers → **orghub-ctf** → ▶ / ⏹.

**Or the terminal:**

```bash
cd ~/ctf-labs/web-intermediate-02
docker compose up -d          # start (builds first time)
docker compose stop           # stop (keeps it; restart later)
docker compose start          # start again
docker compose logs -f        # watch server logs
docker compose down           # remove entirely (fresh reset next 'up')
```

Open http://localhost:8081 (or http://claudectf:8081).

> ⚠️ **State note:** flags and roles live in an in-container database that resets on
> every `up`. If you escalate your account and want to start clean, `down` then `up`.

## Your foothold

You're given one low-privileged account: **`alice`** / **`Password1!`**.
That's it. Everything else you have to *earn* by abusing the app's access controls.

## The mission

**3 flags**, format `FLAG{...}`, increasing difficulty. Each is a different member of
the **Broken Access Control** family — the #1 category in the OWASP Top 10 and the
bread-and-butter of real web assessments:

1. **Horizontal access** — the app shows you *your* data. Can you see someone else's?
2. **Function-level access** — some pages aren't linked in the UI. Are they actually protected, or just hidden?
3. **Privilege escalation** — you're a `user`. The flag is `admin`-only. The password isn't the way in — the app is.

> 💡 Flag 3 can't be done from the browser UI alone — the form won't send what you need.
> This is where your **Burp** setup earns its keep: intercept the request and add a field.

## Rules of the game (with your coach)

- **Black-box first.** Poke the app before reading `app.py`.
- Ask me **"hint"** for a nudge, **"I'm really stuck"** for a stronger one. I won't spoil.
- Tell me what you're seeing and what you've tried — that's how I point you right.

## Suggested toolkit

- Browser + **DevTools** (Network tab)
- **Burp Suite** — required for Flag 3 (intercept + tamper a POST)
- `curl` — great for replaying requests with tweaked parameters

Good luck. Start at http://localhost:8081, log in as alice, and look around.
