# 🔑 Keyring — Advanced Network / Linux CTF (boot2root)

A box built around two skills you haven't drilled yet: **offline password
cracking** and **Linux capabilities**. You break in through a web flaw that leaks
a *hash* (not a plaintext), crack it with your own tooling, then escalate through
a privilege class that isn't SUID, isn't sudo, and isn't cron.

**Authorized target: this box only.**

## Run it

Compose project name: **`keyring-ctf`**.

| Host port | Service | Notes |
|-----------|---------|-------|
| **8085**  | HTTP (web app) | …8082=Sentry, 8083=Relay, 8084=Forge → 8085 |
| **2225**  | SSH | foothold after you crack the hash (2222–2224 taken) |

```bash
cd ~/security-lab/ctfs/net-advanced-08
docker compose up -d --build
docker compose logs -f
docker compose down
```

Web at http://localhost:8085, SSH on `localhost:2225`.

> ⚠️ Flags baked in at build time. `down` + `up --build` = clean reset. Runs
> alongside the other boxes (unique ports).

## The mission — 3 flags

1. **Web LFI → leak a hash (`flag1`).** The documentation viewer opens files by
   name with no sanitization. Escape the docs directory (path traversal) to read
   what ops forgot to delete — a credential backup containing a password **hash**
   and the first flag.
2. **Crack it → foothold (`user.txt`).** The hash won't log you in — you have to
   recover the *plaintext* offline. Crack it with `john` or `hashcat` against
   `rockyou`, then SSH in as the user and read `user.txt`.
3. **Privilege escalation (`root.txt`).** `sudo -l` is a dead end and there's no
   juicy SUID binary. Enumerate **Linux capabilities** — a binary on this box has
   one that hands you root directly.

## How to think about it (what's new)

- **LFI / path traversal.** When a param names a file, try to walk out of the
  intended folder: `?file=../../../../etc/passwd`. Absolute paths often work too
  (`?file=/etc/passwd`). Read `/etc/passwd` to enumerate users, then hunt the
  app's own files for secrets (the changelog drops a hint about where a backup
  lives).
- **You get a hash, not a password.** `$1$...` is **md5crypt**. That's an offline
  cracking job, and it's exactly what your lab is built for:
  ```bash
  echo 'keeper:$1$....' > hash.txt
  john --wordlist=~/wordlist/passwords/rockyou.txt hash.txt        # auto-detects md5crypt
  john --show hash.txt
  # or hashcat: hashcat -m 500 hash.txt ~/wordlist/passwords/rockyou.txt
  ```
- **Capabilities are the sneaky privesc.** SUID isn't the only way a binary runs
  privileged. File *capabilities* grant slices of root power. Enumerate them:
  ```bash
  getcap -r / 2>/dev/null
  ```
  A binary with **`cap_setuid`** can call `setuid(0)` and become root — even
  though it's not SUID and `find -perm -4000` never shows it. That's the trap.

## Suggested toolkit

- **nmap**, **curl**/browser/Burp for the LFI.
- **john** (jumbo) / **hashcat** (your M1 GPU via Metal) + `~/wordlist/passwords/rockyou.txt`.
- **ssh** — `ssh keeper@localhost -p 2225` after cracking.
- **Local enum** — `id`, `sudo -l`, `getcap -r / 2>/dev/null`, and check GTFOBins
  for whatever capability/binary you find.

## Rules of the game (with your coach)

- **Black-box.** nmap first, enumerate the web app, build the picture.
- Tell me what you ran and what came back — that's how I aim the next hint.
- **"hint"** for a nudge, **"I'm really stuck"** for more.
- Mindset checks: (1) a file-by-name feature is asking *"which file can I make it
  open instead?"* (2) a hash is not a login — it's a cracking job. (3) when
  `find -perm -4000` is empty, the privesc may be hiding in `getcap`.

First move: `nmap -sV -p 2225,8085 localhost`, then open the doc viewer and try to
make it read a file it shouldn't.
