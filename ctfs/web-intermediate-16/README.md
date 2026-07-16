# ⚙️ Cogwheel CI — Intermediate Web CTF (a CHAINED box)

An internal continuous-integration / build-artifact server. Like Mailroom, this is **one
attack path**, not four isolated puzzles: four different weaknesses, each one the key that
unlocks the next. You cannot reach flag 4 without walking 1 → 2 → 3.

The four links are new ground for you — none of them appeared on an earlier box:
**JWT forgery → server-side template injection → a known-plaintext ZIP attack →
salted-password cracking.**

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`cogwheel-ctf`**. Publishes on host port **8093**
(Burp keeps 8080; 8081–8092 are earlier CTFs).

```bash
cd ~/security-lab/ctfs/web-intermediate-16
docker compose up -d --build
docker compose logs -f         # watch requests
docker compose down            # stop + remove (fresh state next boot)
```

Open http://localhost:8093.

## The mission — 4 flags, in order

Format `FLAG{...}`. Each stage hands you what the next one needs:

1. **Get admin.** You browse as a guest. Your session is a **signed token** in a cookie —
   but the server is careless about *how* it verifies that signature. Become an admin
   without knowing the signing key. → `flag1` on `/admin`.

2. **Make the server talk.** The admin console has a "build announcement" preview that
   renders your text **server-side**. Make it evaluate something it shouldn't, and pull
   out a secret the app is holding in memory — including the name of a file you'll want
   next. → `flag2`.

3. **Crack the crate.** Download the encrypted artifact bundle from step 2. You don't have
   its password — but you *do* already have the plaintext of one file inside it. That's
   all a legacy-ZIP cipher needs to fall over. → `flag3`, inside the archive.

4. **Crack the credential.** The archive also holds a salted password hash. Recover the
   plaintext and use it where the app asks for it. → `flag4`.

## How to think about it (no spoilers)

- **Recon is in the JS, not robots.txt.** There is no `robots.txt` gift. The endpoints,
  the cookie name, and the token shape are all in the landing page's inline `<script>` and
  in `/api/whoami`. Read your Burp history like an SPA bundle.

- **Flag 1 — a signature you don't have to forge.** Decode the three dot-separated parts of
  your token (they're just base64url — no key needed to *read* them). Look at what the
  **header** claims about the algorithm. A verifier that believes the header will believe
  a token that says it isn't signed at all. What claim decides your access, and can you
  rewrite it? (`jwt.io`, or `base64` + your own tiny script.)

- **Flag 2 — data vs. template.** If your input is `{{ 7*7 }}` and the response says `49`,
  you're not filling a form — you're writing the program. From there, the running app's
  **config object** is reachable, and it's holding more than it should. `{{ config }}` is a
  first thing to try; `.items()` makes it readable.

- **Flag 3 — same bytes, two states.** One member of the encrypted bundle is *also* served
  in the clear somewhere obvious on the site. When you hold both the encrypted and the
  cleartext version of the same data, ZipCrypto (the old PKWARE cipher) is broken — this is
  the classic *known-plaintext attack*. The tool for it is **`bkcrack`**. It wants: the
  archive, the name of the known member, and the cleartext file.

- **Flag 4 — `$6$` means salted SHA-512.** The hash prefix tells you the scheme and the
  salt is right there in the string. Feed it to **john** (pick the matching format, not the
  system `crypt`) or **hashcat** with `rockyou`. It's a quick crack. Then find the one
  place in the app that asks for exactly this password.

## Tooling

- **Browser + DevTools / Burp** — read the inline JS; craft the cookie and the JSON bodies.
- **`bkcrack`** (installed) — the ZipCrypto known-plaintext attack in stage 3.
- **`john` (jumbo)** or **`hashcat -m 1800`** + `~/tools/SecLists/.../rockyou.txt` — stage 4.
- **`curl`** — everything is a plain HTTP/JSON API; `-b "cog_session=<token>"` carries your
  forged session, `-OJ` saves the downloaded artifact with its real name.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
