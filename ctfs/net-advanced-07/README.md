# 🔨 Forge — Advanced Network / Linux CTF (boot2root, 3-hop)

Your hardest box yet, and a deliberate departure from Sentry/Relay. Those two
handed you the foothold — a leaked SSH password. **Forge makes you earn it.** You
break in by *exploiting a live vulnerability*, land as an unprivileged web user,
and then climb through **two** distinct escalations to root.

**Authorized target: this box only.**

## Run it

Compose project name: **`forge-ctf`**. Two services on the host:

| Host port | Service | Notes |
|-----------|---------|-------|
| **8084**  | HTTP (web app) | 8080=Burp, 8081=LinkPeek, 8082=Sentry, 8083=Relay → 8084 |
| **2224**  | SSH | you use this *after* you find a real user's creds (2222/2223 taken) |

```bash
cd ~/security-lab/ctfs/net-advanced-07
docker compose up -d --build   # start (builds first time; compiles a C binary)
docker compose logs -f         # watch it boot
docker compose down            # remove entirely (fresh reset next 'up')
```

Web at http://localhost:8084, SSH on `localhost:2224`. Treat `localhost` as the
target IP.

> ⚠️ **State note:** flags baked in at build time. `down` + `up --build` = clean
> reset. Runs alongside Sentry and Relay — different ports.

## The mission — 3 flags, a 3-hop kill chain

1. **Foothold via exploitation (`flag1`).** No password is handed to you this time.
   Enumerate the web app, find the vulnerability in its diagnostic feature, and
   turn it into **remote code execution**. You land as a low-priv web user
   (`www-data`) — flag 1 proves your code execution.
2. **Lateral movement (`user.txt`).** `www-data` is a dead-end account. Enumerate
   the filesystem *from your web-user shell* and find credentials the app left
   lying around for a **real** user. Become that user (their creds work on SSH).
   The flag is in their home directory — which `www-data` can't even read.
3. **Privilege escalation (`root.txt`).** As that user, hunt for **SUID** binaries.
   One of them is a custom "ops tool" that does something unsafe. Abuse it to run
   your own code as root and read the root-only flag.

## How to think about it (what's new vs Sentry/Relay)

- **The foothold is an exploit, not a leak.** Web apps that shell out to system
  commands (ping, nslookup, whois, image conversion, "run build"…) are a top
  source of **OS command injection**. If input reaches a shell, you can inject:
  try `;`, `|`, `&&`, `$( )`. First prove it (`; id`), then weaponize it.
- **`www-data` → user → root is a *chain*.** You won't jump straight to root.
  Post-exploitation enumeration as the web user is where you find the next hop:
  read the app's own files/config — secrets love to live there.
- **A new priv-esc class: SUID.** `find / -perm -4000 -type f 2>/dev/null` lists
  binaries that run *as their owner* (often root) regardless of who launches them.
  A custom SUID binary is a gift — figure out *what it runs* (`strings`, `ltrace`)
  and whether you can influence it. If it calls another program **by name instead
  of absolute path**, you own its `$PATH`.

## Suggested toolkit

- **nmap** — `nmap -sV -p 2224,8084 localhost`.
- **browser / curl / Burp** — drive the diagnostic form; `curl -d "host=..."` is
  perfect for iterating an injection payload.
- **ssh** — `ssh deploy@localhost -p 2224` once you have the creds (guessing the
  username; you'll confirm it during hop 2).
- **Local enum** — `id`, `sudo -l`, `find / -perm -4000 -type f 2>/dev/null`,
  `strings <suid-binary>`, and read every app file you can (`/var/www/...`).
- **[GTFOBins](https://gtfobins.github.io/)** — still your friend for known SUID
  binaries; but the root step here is a *custom* binary, so you reason about it
  yourself.

## Rules of the game (with your coach)

- **Black-box.** Start from `nmap`, enumerate the web app, build the picture.
- Tell me what you ran and what came back — that's how I aim the next hint.
- Ask me **"hint"** for a nudge, **"I'm really stuck"** for a stronger one.
- Two mindset checks for this box: (1) when input hits a shell, *what character
  ends the intended command and starts yours?* (2) when a root-owned program calls
  a helper *by name*, *who decides which file that name resolves to?*

Good luck. First move: `nmap -sV -p 2224,8084 localhost`, then go poke that
diagnostic form.
