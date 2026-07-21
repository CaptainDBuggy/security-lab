# Dataroom — Advanced Web CTF (a CHAINED box)

A secure document-sharing vault used during corporate acquisitions. Three
**distinct vulnerability classes**:
**JWT algorithm confusion → NoSQL operator injection → YAML deserialization RCE.**

All three techniques are new — you haven't exploited any of them in a CTF
before. The pickle artifact from Gridlock covers deserialization concepts
that transfer directly to the third stage.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`dataroom-ctf`**. Publishes on host port **8099**.

```bash
cd ~/security-lab/ctfs/web-advanced-22
docker compose up -d --build
docker compose logs -f         # watch requests
docker compose down            # stop + remove
```

Open http://localhost:8099.

## The mission — 3 flags, in order

Format `FLAG{...}`. Each stage reveals intel for the next:

1. **Forge an admin token without knowing the password.** The app uses
   JWT authentication with an asymmetric signing algorithm. But the
   verification logic has a classic flaw — it trusts a value from the
   token itself to decide *how* to verify it. Find the public key, then
   exploit the mismatch between asymmetric and symmetric verification.
   → `flag1` is on the admin panel.

2. **Bypass a server-side access check on classified documents.** The
   admin panel has an advanced query endpoint that supports MongoDB-style
   filter operators. There's a server-side check that blocks direct
   queries for classified data — but the check only looks for one
   specific input shape. Find an input shape it doesn't expect.
   → `flag2` is in a classified document.

3. **Achieve code execution through the import feature.** The admin panel
   accepts YAML configuration imports. Research what YAML parsing in
   Python can do when the loader isn't restricted, and what tags give you
   code execution. → `flag3` is in a file on the filesystem.

## How to think about it (no spoilers)

- **Flag 1 — study the JWT.** Decode your JWT token (base64, or
  jwt.io). Note the algorithm in the header. Find where the app exposes
  its public key. Research "JWT algorithm confusion attack" — what
  happens when a server accepts HS256 tokens but verifies them with a
  key that was meant for RS256? You'll need Python (or manual base64 +
  HMAC) to forge the token.

- **Flag 2 — think about types, not values.** The server checks if your
  query asks for "classified" — but it checks for a string. What
  happens when the value isn't a string? The query engine supports
  operators like `$ne`, `$gt`, `$regex`. Can you use one of those to
  match classified documents without the word "classified" appearing as
  a plain string in your query?

- **Flag 3 — this is pickle's cousin.** Python's `yaml.unsafe_load()`
  supports tags that instantiate arbitrary Python objects — just like
  pickle's `__reduce__`. Research `!!python/object/apply` in PyYAML.
  You need to call a function that reads a file. The flag is at
  `/tmp/vault_master_key.txt`.

## Tooling

- **Browser + DevTools** — Application tab for viewing/editing JWT cookies.
- **Python** — For forging JWTs and understanding YAML payloads.
- **curl** — For hitting API endpoints directly.
- **jwt.io** — Handy for decoding (not forging) JWTs.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
