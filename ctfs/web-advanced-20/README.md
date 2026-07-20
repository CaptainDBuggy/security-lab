# Patchwork — Advanced Web CTF (a CHAINED box)

A code snippet sharing platform. Three **distinct vulnerability classes**,
each harder than the last: **JWT cracking → SSTI → Path traversal bypass.**

This is a step up from the intermediate boxes. Less hand-holding, more
research required. Each exploit needs a technique you haven't used in a
CTF yet.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`patchwork-ctf`**. Publishes on host port **8097**.

```bash
cd ~/security-lab/ctfs/web-advanced-20
docker compose up -d --build
docker compose logs -f         # watch requests
docker compose down            # stop + remove
```

Open http://localhost:8097.

## The mission — 3 flags, in order

Format `FLAG{...}`. Each stage reveals intel for the next:

1. **Forge an admin token.** The app uses token-based authentication.
   Study the token format — it's a standard you should recognize. The
   signing is only as strong as the secret behind it. Crack it, forge
   a new token with elevated privileges. → `flag1` is on the admin panel.

2. **Exploit the template engine.** The admin panel has a feature that
   renders user-supplied templates server-side. The template engine is
   more powerful than the developers intended — it can reach deep into
   Python's runtime. Some dangerous keywords are blocked, but file
   reads aren't. → `flag2` in a file at the root of the filesystem.

3. **Escape the snippets directory.** The admin panel has a file download
   feature. It has protection against directory traversal, but the
   sanitization has a flaw — it doesn't account for what happens when
   you remove a pattern from the middle of a longer pattern. → `flag3`
   in a file at the root of the filesystem.

## How to think about it (no spoilers)

- **Flag 1 — recognize the format.** The token has three parts separated
  by dots. Each part is base64url-encoded. This is a well-known standard
  with well-known attack tools. The header tells you the algorithm, and
  the algorithm tells you what you need to crack. Wordlists work.

- **Flag 2 — template injection.** Start simple: does `{{7*7}}` return
  49? If the engine evaluates expressions, how far can you go? In Python,
  every object has a class, every class has a hierarchy, and that
  hierarchy has access to powerful built-in functions. Research "Jinja2
  SSTI" — the technique is well-documented.

- **Flag 3 — think about the filter.** If a filter removes `../` from
  your input, what happens if your input contains a string that
  *becomes* `../` after the removal? Write it out on paper.

## Tooling

- **Browser + DevTools** — Application tab for cookies is critical
  for flag 1.
- **jwt.io** — Paste the token to inspect its structure. Don't trust
  it for cracking though.
- **hashcat / john / jwt_tool** — For cracking the token secret.
  `hashcat -m 16500 -a 0 token.txt wordlist.txt` is one approach.
- **Burp Suite** — Repeater for template injection and download
  parameter fuzzing.
- **HackTricks / PayloadsAllTheThings** — Research SSTI payloads for
  Jinja2. Understanding beats copy-pasting.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
