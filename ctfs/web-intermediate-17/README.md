# 📟 Loglet — Intermediate Web CTF (a CHAINED box)

An internal incident-log & alerting portal. Like the last two boxes, this is **one attack
path**, not three isolated puzzles: three different bugs, each one the key to the next. You
can't reach flag 3 without walking 1 → 2.

The three links round out primitives you hadn't chained yet:
**UNION-based SQL injection → arbitrary file read (LFI) → OS command injection.**

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`loglet-ctf`**. Publishes on host port **8094**
(Burp keeps 8080; 8081–8093 are earlier CTFs).

```bash
cd ~/security-lab/ctfs/web-intermediate-17
docker compose up -d --build
docker compose logs -f         # watch requests
docker compose down            # stop + remove (fresh DB + new tokens next boot)
```

Open http://localhost:8094.

> The DB, config token, and admin password are regenerated on every boot. `docker compose
> down && docker compose up -d` gives a clean slate.

## The mission — 3 flags, in order

Format `FLAG{...}`. Each stage hands you what the next one needs:

1. **Get admin.** The public **incident search** talks to a SQL database, and it isn't
   careful about how it builds the query. You have no account — pull the operators' table
   out through the search and sign in as admin. → `flag1` on `/dashboard`.

2. **Read what isn't served.** The admin **report viewer** opens files by name. It'll open
   more than reports if you ask it to. Read the service's own config off disk — it holds a
   flag *and* a token you'll need next. → `flag2`.

3. **Run a command.** The admin **connectivity check** runs a real shell command against a
   host you supply, and it's gated by the token from step 2. Make it run a command of
   *yours* and read the flag file off disk. → `flag3`.

## How to think about it (no spoilers)

- **Recon is in the JS, not robots.txt.** No `robots.txt` gift. The endpoints and their
  parameters (`/api/search?q=`, `/report?file=`, `/api/maintenance`) are in the inline
  `<script>` on each page and in your Burp history. Read it like an SPA bundle.

- **Flag 1 — count the columns, then borrow the query.** Start by breaking the query with a
  lone quote and reading the error. The results table shows **three** columns — that's your
  UNION width. `... ORDER BY 3`/`ORDER BY 4` confirms it, then
  `UNION SELECT a,b,c` lets you select from *another* table. What table holds logins, and
  what are its columns? (`sqlmap` would walk this for you, but do the first one by hand —
  you want to *see* the column-count/UNION mechanic.)

- **Flag 2 — "by name" is a path.** If a filename goes into `open()` with no containment,
  then an **absolute path** (`/app/config.ini`) or `../` climbs wherever the process can
  read. `/etc/passwd` proves the primitive; the config file is the loot. Where would an app
  keep its config?

- **Flag 3 — the box pings for you; make it do more.** A connectivity check that runs
  `ping <your input>` through a shell is one metacharacter away from running two commands.
  `;`, `|`, `&&`, `$(...)` all chain a second command onto the first. You need the
  maintenance token from step 2 to reach it. What file did the Dockerfile drop for you to
  read?

## Tooling

- **Browser + DevTools / Burp** — read the inline JS; craft the injection and the JSON
  bodies. Burp Repeater is ideal for iterating the UNION payload.
- **`curl`** — everything is a plain HTTP/JSON API. `--data-urlencode "q=..."` keeps your
  SQLi payload intact; `-c jar -b jar` carries the admin session after login.
- **`sqlmap`** (installed) — fair game once you've done the manual UNION, to see it
  automate the same extraction (`-u '.../api/search?q=network' --dump -T operators`).

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
