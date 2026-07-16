# 🔐 Sesame — Intermediate Web CTF (Broken Authentication)

A team single-sign-on portal. **New primitive:** Ledgr (CTF 12) was broken *authorization*
— the app didn't check *what you're allowed to do*. Sesame is broken *authentication* —
the app doesn't properly verify *who you are*. Sibling bug class, different half of the
"who are you / what can you do" pair, and OWASP top-tier.

You log in as **`alice` / `hunter2`**, an ordinary user.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`sesame-ctf`**. Publishes on host port **8090**
(Burp keeps its default 8080; 8081–8089 are earlier CTFs).

```bash
cd ~/security-lab/ctfs/web-intermediate-13
docker compose up -d --build   # start
docker compose logs -f         # watch requests
docker compose down            # stop + remove
```

Open http://localhost:8090.

> The one bit of state that changes is account passwords (via the reset flow).
> `docker compose down && docker compose up -d` gives you a clean slate.

## The mission — 3 flags

Format `FLAG{...}`. **Every flag is a broken-authentication failure**, escalating:

1. **Predictable password-reset token.** The reset flow hands out a token that's
   *derived from something public*, not random. Your own account's reset link is shown
   to you (dev build) — study it, work out the algorithm, then forge the token for an
   account you don't own and take it over → `flag1`.

2. **JWT `alg:none` forgery.** Your `session` cookie is a JWT. Decode it and look at the
   claims. The server's verifier has a classic flaw in how it handles the `alg` header —
   exploit it to forge a token asserting a privilege level **no real account has**, and
   reach `/console` → `flag2`.

3. **Leftover debug endpoint.** There's a diagnostics endpoint shipped to "prod" with no
   auth. It's **not linked in the UI, and there's no robots.txt to hand it to you** — you
   find it the way you would in a real assessment: **read the client-side JavaScript** the
   app serves and look for endpoint references → `flag3`.

## How to think about it

- **Authentication tokens are data — inspect and question them.** A reset token, a
  session cookie, a "remember me" value: decode it, ask how it was generated, ask what
  happens if you change it.
- **Predictable ≠ secret.** If a token is `hash(something you know)`, you can regenerate
  it for anyone. Reverse the scheme from a token you *are* allowed to see (your own).
- **JWTs: trust the signature, not the claims — and check who's deciding the algorithm.**
  The header says how the token was signed. What if it says it wasn't? Decode with
  `base64 -d` (JWTs are base64url, no padding — add `=` back or use a JWT tool).
- **Endpoints aren't only what the UI links.** Served JS, source comments, and fuzzing
  reveal routes the page never shows you. Grep the JavaScript for paths.

## Tooling

- **Browser + DevTools** — Application tab to read/edit the `session` cookie; Sources/
  Network to read the served JS.
- **`curl`** — replay the reset POST, hit `/console` with a forged cookie, GET the debug
  endpoint. (`printf '%s' <b64> | base64 -d` to decode; `md5` / `md5sum` for the token.)
- **Burp** (8080) — repeater is handy for swapping the `session` cookie.
- A JWT tool (jwt.io, `jwt` CLI, or hand-rolled base64url) helps for flag 2 — but you can
  forge an `alg:none` token with `base64` alone.

## Stop / remove

```bash
docker compose down     # stop + remove (also resets passwords)
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
