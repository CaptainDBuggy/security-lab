# 📒 Ledgr — Intermediate Web CTF (Broken Access Control / IDOR)

A small-team billing portal. **New primitive:** you've drilled SQLi and XSS — this box
is about **broken access control**, the #1 item on the OWASP Top 10. Different muscle:
no injection, no payloads. The bug is that the app lets an *authenticated* user touch
objects and functions they were never *authorised* for.

You log in as **`alice` / `hunter2`**, an ordinary customer. Your session is perfectly
legitimate — the whole game is reaching things Alice shouldn't.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`ledgr-ctf`**. Publishes on host port **8089**
(Burp keeps its default 8080; 8081–8088 are earlier CTFs).

**Docker Desktop GUI:** Containers → **ledgr-ctf** → ▶ / ⏹.

**Or the terminal:**

```bash
cd ~/security-lab/ctfs/web-intermediate-12
docker compose up -d --build   # start
docker compose logs -f         # watch requests
docker compose down            # stop + remove
```

Open http://localhost:8089 and sign in (the form is pre-filled with Alice's creds).

> Stateless box — nothing you do mutates server state, so there's no reset. Just
> re-request.

## The mission — 3 flags

Format `FLAG{...}`. **Every flag is a missing authorization check.** Same primitive,
three escalating flavours:

1. **Sequential IDOR.** Your dashboard links to *your* invoices at `/invoice/<id>`.
   The server fetches an invoice by id and renders it **without checking you own it**.
   The ids are small integers. Read a customer that isn't you → `flag1`.

2. **IDOR behind an "opaque" token.** Your statement link is
   `/statement?token=<something>`. It looks random. It isn't — it's just a wrapper
   around an account id. **Decode it, change the id, re-encode.** Encoding is not
   access control → `flag2`.

3. **Broken function-level authz.** There's an admin area. The **page** at `/admin`
   correctly slams non-admins with a `403`. But the **action** behind its button —
   the thing that actually dumps data — forgot to check your role. Find that endpoint
   (the app even tells you where admin tools live if you look in the right place) and
   call it directly → `flag3`.

## How to think about it

- **Authenticated ≠ authorized.** You *are* logged in. That's not permission to see
  someone else's data. On every request ask: *did the server check this belongs to me?*
- **Enumerate.** IDOR lives on identifiers — integers, tokens, filenames, UUIDs in a
  response. When you see one, ask what happens if you change it.
- **Opaque ≠ secure.** Base64, hex, a hash-looking string — treat every "random" token
  as decodable until proven otherwise. Decode first, *then* decide if it's real crypto.
- **Hidden ≠ protected.** A button the UI doesn't render for you is not a security
  control. Under the hood, is the *endpoint* checking your role, or just the page that
  linked to it? Protecting the page and forgetting the action is one of the most common
  real-world access-control bugs.

## Tooling

- **Browser + DevTools** — you'll be editing URLs and reading responses.
- **Burp** (8080) or `curl` — handy for hitting endpoints directly, decoding tokens,
  and replaying requests with a tweaked id. (`base64 -d` decodes the token; note it's
  URL-safe base64.)
- **`curl -b`** with your `sid` cookie replays authenticated requests from the terminal.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
