# 🔗 LinkPeek — Advanced Web CTF

A link-preview service with a **Server-Side Request Forgery (SSRF)** flaw. You
give it a URL, the **server** fetches it, and you can steer that fetch at things
the server can reach but you can't. Everything runs locally in Docker.
**Authorized target: this box only.**

## Run it

Compose project name: **`linkpeek-ctf`**. Publishes on host port **8081**
(Burp keeps its default 8080, so you can proxy freely).

**Docker Desktop GUI:** Containers → **linkpeek-ctf** → ▶ / ⏹.

**Or the terminal:**

```bash
cd ~/security-lab/ctfs/web-advanced-04
docker compose up -d          # start (builds first time)
docker compose stop           # stop (keeps it; restart later)
docker compose start          # start again
docker compose logs -f        # watch server logs
docker compose down           # remove entirely (fresh reset next 'up')
```

Open http://localhost:8081 (or http://claudectf:8081).

> ⚠️ **State note:** the flags are baked into the image at build time. A plain
> `docker compose restart` keeps them; a `down` + `up` rebuilds clean.

## The setup

There's a public box and a private one, both inside the same container:

- **Public app** — the LinkPeek preview form, on port **8081** (what you can reach).
- **Internal ops service** — bound to **loopback:8090**, *not* published. You
  cannot connect to it directly from your machine. The server can. That gap is
  the game.

No login. The entire attack surface is the "paste a URL, get a preview" box.

## The mission

**3 flags**, format `FLAG{...}`, increasing difficulty. All come off the same
SSRF, each reaching further:

1. **Reach the internal service.** There's an ops console the server can see and
   you can't. A host filter tries to stop you from naming internal addresses — but
   it only knows a few spellings of "internal." Find one it forgot.
2. **Steal cloud credentials.** Real cloud boxes expose an instance **metadata**
   service that hands out the machine's IAM keys to anything that asks from
   inside. This box mirrors one. Pivot to it and loot the credentials.
3. **Change protocols.** The fetcher was written as if URLs are always web pages.
   They aren't. There's a local file — root-only on disk, served by no route —
   that the fetcher will happily read if you ask it in the right *scheme*. (The
   internal console tells you where to look.)

> 💡 SSRF filters that blocklist strings like `127.0.0.1` are famous for missing
> the *other* ways to write the same destination. Part of Flag 1 is knowing a
> handful of those by heart.

## Rules of the game (with your coach)

- **Black-box first.** Try the preview on a normal URL, then ask what else the
  server might fetch.
- Watch the difference between an *error* (the server tried and failed to reach
  something) and a *block* (the filter refused). Errors are recon gold — they
  tell you what's actually listening.
- Ask me **"hint"** for a nudge, **"I'm really stuck"** for a stronger one.
- Tell me what URL you sent and what came back.

## Suggested toolkit

- Browser + **DevTools**, or **Burp** Repeater to iterate URLs fast
- `curl` one-liner:
  `curl -s localhost:8081/peek --data-urlencode 'url=http://example.com/'`
- Worth memorizing: the many ways to write `127.0.0.1`, and which URL **schemes**
  a fetching library will accept besides `http`.

Good luck. Start at http://localhost:8081 and think about *who* is really making
the request.
