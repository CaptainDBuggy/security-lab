# Mint — Advanced Web CTF (a CHAINED box)

A digital currency platform. Three **distinct vulnerability classes**:
**JavaScript source review → Race condition (TOCTOU) → Predictable token forgery.**

All three techniques are new — you haven't exploited any of them in a
CTF before. The race condition is especially important: it's one of the
most impactful bug classes in production financial systems.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`mint-ctf`**. Publishes on host port **8100**.

```bash
cd ~/security-lab/ctfs/web-advanced-23
docker compose up -d --build
docker compose logs -f         # watch requests
docker compose down            # stop + remove
```

Open http://localhost:8100.

## The mission — 3 flags, in order

Format `FLAG{...}`. Each stage reveals intel for the next:

1. **Find the hidden internal endpoint.** The app serves a JavaScript
   file. Read the source — it contains a reference to an undocumented
   diagnostics endpoint and its required authentication header. Access
   the endpoint for `flag1` and information about the system's
   internals.

2. **Exploit the transfer system.** The diagnostics output warns about a
   non-atomic balance check. The transfer endpoint checks your balance,
   then processes, then deducts — but what happens if many requests hit
   the check at the same time? You start with 500 MC. Premium Status
   costs 10,000 MC. You'll need to create coins that shouldn't exist.
   Buy Premium for `flag2`.

3. **Take over the admin account.** Premium intel reveals how the
   password reset system generates tokens. The generation is predictable,
   and the API leaks the one input you'd need to reproduce it. Forge the
   admin's reset token, reset their password, and access the vault for
   `flag3`.

## How to think about it (no spoilers)

- **Flag 1 — read the client-side source.** Open the JS file the page
  loads and read it carefully. Look for endpoint paths and authentication
  values that shouldn't be in client code. Use `curl` with custom
  headers to hit what you find.

- **Flag 2 — think about concurrency.** The balance check and deduction
  are separate operations with a gap between them. If 20 requests all
  check the balance at the same time, they all see 500 MC — and all
  proceed. You'll need Python threading, `curl` in a loop, or a similar
  tool to send many simultaneous requests. Create a second account as the
  transfer recipient.

- **Flag 3 — reverse the token algorithm.** The hint from flag 2 tells
  you the hash function and inputs. The API response gives you the
  timestamp. You just need to combine them the way the server does.
  Python's `hashlib` module will get you there in two lines.

## Tooling

- **Browser + DevTools** — Sources tab to read the JS file.
- **curl** — For hitting the diagnostics endpoint with custom headers.
- **Python** — Required for the concurrent race exploit and token forging.
- **Burp Suite** — Useful for inspecting API responses.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
