# 📡 Relay — Intermediate+ Network / Linux CTF (boot2root)

Your **second** boot2root, and a deliberate step up from Sentry. Same OSCP loop —
scan, enumerate, foothold, escalate — but this box punishes shortcuts:

- **Recon is less generous.** `robots.txt` points you at a *dead end*. The thing
  you actually want is not signposted; you have to brute-force directories to
  find it.
- **The root step is NOT a GTFOBins one-liner.** `sudo -l` is a dead end on
  purpose. You escalate by *finding a misconfiguration* through local enumeration
  — not by recalling a magic command.

**Authorized target: this box only.**

## Run it

Compose project name: **`relay-ctf`**. Publishes two services on the host:

| Host port | Service | Notes |
|-----------|---------|-------|
| **8083**  | HTTP (web app) | 8080=Burp, 8081=LinkPeek, 8082=Sentry, so Relay takes 8083 |
| **2223**  | SSH | your foothold (2222=Sentry, so Relay takes 2223) |

```bash
cd ~/security-lab/ctfs/net-intermediate-06
docker compose up -d --build   # start (builds first time)
docker compose logs -f         # watch it boot
docker compose down            # remove entirely (fresh reset next 'up')
```

Treat `localhost` as the target's IP. Web at http://localhost:8083, SSH on
`localhost:2223`. (`claudectf` resolves to the same 127.0.0.1 if you prefer a
hostname.)

> ⚠️ **State note:** flags are baked into the image at build time. `down` + `up
> --build` rebuilds clean. Runs happily alongside Sentry — different ports.

## The mission — 3 flags (`FLAG{...}`), the kill chain

1. **Recon & information disclosure.** Scan the box, enumerate the web service.
   This time robots.txt lies — brute-force directories to find what ops left
   exposed. The first flag (and your way in) is in it.
2. **Foothold (`user.txt`).** Turn what you found into a shell as a low-priv
   service account. The flag is in that user's home directory.
3. **Privilege escalation (`root.txt`).** `sudo -l` will not save you here.
   Enumerate the box: what runs automatically, and what can *you* write to that
   *root* runs? Abuse it to become root and read the flag only root can see.

## How to think about it (what's new vs Sentry)

- **Directory brute-forcing is mandatory, not optional.** `gobuster dir -u
  http://localhost:8083 -w ~/tools/SecLists/Discovery/Web-Content/common.txt`.
  robots.txt is a distraction; the real path is discovered, not disclosed.
- **When `sudo -l` is empty, you are not done — you are just getting started.**
  Priv-esc lives in *everything the box does on its own*: scheduled jobs (cron),
  services, SUID binaries, writable files owned by root. Enumerate all of it.
- **Two questions that crack this box:** (1) *What runs as root without me?*
  (`cat /etc/crontab`, `ls -la /etc/cron.d/`, `ps aux`). (2) *What can I write to
  that something important reads or runs?*
  (`find / -writable -type f 2>/dev/null`, look for world-writable `-perm -0002`).

## Suggested toolkit

- **nmap** — `nmap -sV -p 2223,8083 localhost` (or `-p-` to discover ports).
- **gobuster / ffuf** — directory brute-forcing (you *need* this here).
- **curl** / browser + Burp — read what the web app serves.
- **ssh** — `ssh svc@localhost -p 2223` once you have the password.
- **Local enum** — `sudo -l` (dead end, confirm it), `id`, `crontab -l`,
  `cat /etc/crontab`, `ls -la /etc/cron.d/`, `find / -perm -0002 -type f 2>/dev/null`.
  This is the LinPEAS mindset done by hand.

## Rules of the game (with your coach)

- **Black-box.** Start from `nmap` and build the picture yourself.
- Tell me what you ran and what came back — that's how I aim the next hint.
- Ask me **"hint"** for a nudge, **"I'm really stuck"** for a stronger one.
- When you hit the priv-esc and `sudo -l` gives you nothing: **don't ask me, ask
  the box.** What does it do on a timer? That is the whole challenge.

Good luck. First move as always: `nmap -sV -p 2223,8083 localhost`.
