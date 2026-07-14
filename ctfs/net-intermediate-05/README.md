# 🛰️ Sentry — Intermediate Network / Linux CTF (boot2root)

Your first **non-web** box. This isn't "find the bug in one app" — it's the full
**OSCP loop**: scan the host, enumerate what's listening, find a way in, land a
low-privilege shell, then escalate to **root**. Everything runs locally in Docker.
**Authorized target: this box only.**

## Run it

Compose project name: **`sentry-ctf`**. Publishes two services on the host:

| Host port | Service | Notes |
|-----------|---------|-------|
| **8082**  | HTTP (web app) | 8080=Burp, 8081=LinkPeek, so Sentry takes 8082 |
| **2222**  | SSH | this is how you get your foothold |

**Docker Desktop GUI:** Containers → **sentry-ctf** → ▶ / ⏹.

**Or the terminal:**

```bash
cd ~/ctf-labs/net-intermediate-05
docker compose up -d          # start (builds first time)
docker compose logs -f        # watch it boot
docker compose down           # remove entirely (fresh reset next 'up')
```

Treat `localhost` as the target's IP. Web at http://localhost:8082, SSH on
`localhost:2222`.

> ⚠️ **State note:** flags are baked into the image at build time. `down` + `up`
> rebuilds clean.

## The mission — 3 flags (`FLAG{...}`), the kill chain

1. **Recon & information disclosure.** Scan the box, enumerate the web service,
   and find something the ops team left exposed that they really shouldn't have.
   The first flag is sitting in it — and so is your way in.
2. **Foothold (`user.txt`).** Turn what you found in step 1 into an actual shell
   on the box as a low-privilege user. The flag is in that user's home directory.
3. **Privilege escalation (`root.txt`).** You're not root yet. Enumerate what your
   user is *allowed* to do that it shouldn't be, abuse it to become root, and read
   the flag only root can see.

## How to think about it (the OSCP loop)

1. **Enumerate** — what ports are open? What's the service + version on each?
   `nmap -sV` is your first move on any box, always.
2. **Web enum** — a webserver is never just the homepage. Check `robots.txt`,
   brute-force directories, read every file you find. Ops teams leak secrets in
   backups, notes, and configs.
3. **Foothold** — credentials found in one place are reused in another. That's
   the single most common way real boxes fall.
4. **Post-exploitation enum** — the moment you land a shell, enumerate *locally*:
   who am I, what can I run, what's SUID, what does `sudo -l` say?
5. **Privilege escalation** — one misconfiguration is usually all it takes.

## Suggested toolkit

- **nmap** — `nmap -sV -p- localhost` (all ports) then focus with `-sV -sC`
- **gobuster / ffuf** — directory brute-forcing against the web app
  (`~/tools/SecLists` has wordlists — try `Discovery/Web-Content/common.txt`)
- **curl** / browser + Burp — read what the web app serves
- **ssh** — your foothold client
- **`sudo -l`, `find / -perm -4000`, LinPEAS mindset** — local priv-esc enumeration
- **[GTFOBins](https://gtfobins.github.io/)** — bookmark it. When you find a binary
  you can run as root, this tells you how to weaponize it. This box's root step is
  a textbook GTFOBins entry.

## Rules of the game (with your coach)

- **Black-box.** Start from `nmap localhost` and build the picture yourself.
- Distinguish **open-but-boring** from **open-and-interesting**. Every service is a
  question: what can I *do* with this?
- Ask me **"hint"** for a nudge, **"I'm really stuck"** for a stronger one.
- Tell me what you ran and what came back — that's how I aim the next hint.

Good luck. `nmap -sV -p 2222,8082 localhost` is a fine first command. Think about
*what the ops team forgot to clean up.*
