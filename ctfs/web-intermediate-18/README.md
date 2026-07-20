# 🗄️ Archivex — Intermediate Web CTF (a CHAINED box)

A company document archive and reporting platform. Three **distinct vulnerability
classes**, each unlocking the next: **IDOR → XXE → Python code injection.**

Unlike some boxes, the attack surface is spread across the app — each flag lives
behind a different endpoint and a different exploit. Recon matters.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`archivex-ctf`**. Publishes on host port **8095**
(Burp keeps 8080; 8081–8094 are earlier CTFs).

```bash
cd ~/security-lab/ctfs/web-intermediate-18
docker compose up -d --build
docker compose logs -f         # watch requests
docker compose down            # stop + remove (fresh DB + creds next boot)
```

Open http://localhost:8095.

> The DB, config, and admin password are regenerated on every boot.
> `docker compose down && docker compose up -d` gives a clean slate.

## The mission — 3 flags, in order

Format `FLAG{...}`. Each stage reveals intel for the next:

1. **Read a restricted document.** The archive API returns a document count
   that doesn't match how many you can see. Something's hidden — and the API
   doesn't check whether you're allowed to read it. → `flag1` is in a
   restricted document, along with credentials and an endpoint you'll need.

2. **Exploit the import service.** Use the credentials from flag 1 to log in.
   The import endpoint accepts XML — and the parser is too trusting. Read a
   config file off disk. → `flag2` and the admin password.

3. **Abuse the calculator.** Log in as admin. The admin panel has a metric
   calculator that evaluates expressions server-side — and it's more powerful
   than it should be. Some dangerous functions are blocked, but the blocklist
   has gaps. Read a flag file from disk. → `flag3`.

## How to think about it (no spoilers)

- **Start with recon.** Open DevTools. Read every `fetch()` call in the inline
  JS. The API responses have more data than the page shows — look at the raw
  JSON, including metadata fields like counts.

- **Flag 1 — check the math.** The listing says there are N total documents but
  shows fewer. Where are the rest? The detail endpoint takes an ID. Try the
  ones you haven't seen.

- **Flag 2 — you know this one.** You recently learned a technique that lets an
  XML parser read files for you. The import endpoint uses the same kind of
  vulnerable parser. Where does a Python app keep its config? The XML format
  changed — adapt the payload.

- **Flag 3 — what language is the backend?** The calculator evaluates
  expressions. What happens if the expression is valid Python? Some functions
  are blocked — but which ones *aren't*? Python has a built-in way to read
  files that doesn't need any imports.

## Tooling

- **Browser + DevTools** — Network tab is critical for recon. Watch the API
  responses closely.
- **Burp Suite** — Repeater for crafting the XXE payload and testing calculator
  expressions.
- **`curl`** — good for quick API probing; `-c jar -b jar` carries sessions
  across requests.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
