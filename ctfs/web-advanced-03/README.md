# 📨 PostPilot — Advanced Web CTF

A campaign-message preview tool with a **Server-Side Template Injection (SSTI)**
flaw that escalates to **remote code execution**. Everything runs locally in
Docker. **Authorized target: this box only.**

## Run it

Compose project name: **`postpilot-ctf`**. Publishes on host port **8081**
(Burp keeps its default 8080, so you can proxy freely).

**Docker Desktop GUI:** Containers → **postpilot-ctf** → ▶ / ⏹.

**Or the terminal:**

```bash
cd ~/security-lab/ctfs/web-advanced-03
docker compose up -d          # start (builds first time)
docker compose stop           # stop (keeps it; restart later)
docker compose start          # start again
docker compose logs -f        # watch server logs
docker compose down           # remove entirely (fresh reset next 'up')
```

Open http://localhost:8081 (or http://claudectf:8081).

> ⚠️ **State note:** the disk flag and the environment flag are baked into the
> image at build time. A plain `docker compose restart` keeps them; a `down` +
> `up` rebuilds clean.

## The setup

No login this time. PostPilot lets you write a notification **template** with
placeholders like `{{ name }}` and previews the rendered message against a sample
recipient. That's the whole app — and the whole attack surface.

## The mission

**3 flags**, format `FLAG{...}`, increasing difficulty. All three come off the
**same injection point** — what changes is how deep you go:

1. **Confirm & leak** — is the placeholder engine *only* substituting your
   fields, or will it evaluate whatever you write? If it evaluates, the server's
   own context is holding a secret it never meant to render.
2. **Break out** — a template engine hands you a doorway into the language's
   object graph. Walk it until you reach something that can spawn a process, then
   run a command and read a file that **no URL will ever serve you**.
3. **Loot** — code execution isn't the prize, it's the tool. Real attackers
   immediately rifle the process **environment**, where apps stash credentials
   and keys. One of them is your third flag.

> 💡 The app has a "content filter" that rejects templates containing scary
> keywords. It is not as clever as it thinks. Part of the lesson is *why*
> blocklists fail against this class of bug — you should not need any of the
> words it blocks.

## Rules of the game (with your coach)

- **Black-box first.** Poke the preview form before reading `app.py`.
- Start by proving injection with a tiny arithmetic payload. If `{{ 7*7 }}`
  comes back as `49`, you're not in a string-substitution engine anymore.
- Ask me **"hint"** for a nudge, **"I'm really stuck"** for a stronger one.
  I won't spoil.
- Tell me what you send and what comes back — the render errors are shown on
  purpose, and they're your best debugging signal.

## Suggested toolkit

- Browser + **DevTools** (Network tab)
- **Burp Suite** — great for iterating payloads quickly (Repeater is your friend)
- `curl` — one-liner payload replay:
  `curl -s localhost:8081/preview --data-urlencode 'template={{ 7*7 }}'`

Good luck. Start at http://localhost:8081 and see what the preview *really* does
with your template.
