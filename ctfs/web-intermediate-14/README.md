# 📡 NetProbe — Intermediate Web CTF (OS Command Injection)

An internal network-diagnostics console (ping / DNS lookup / uptime monitor). **New
primitive:** you've injected into a *database* (SQLi) and a *browser* (XSS). NetProbe
injects into a **shell** — user input reaches an OS command, and command injection is
usually a straight line to remote code execution.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`netprobe-ctf`**. Publishes on host port **8091**
(Burp keeps its default 8080; 8081–8090 are earlier CTFs).

```bash
cd ~/security-lab/ctfs/web-intermediate-14
docker compose up -d --build   # first build installs ping/nslookup — slightly slow
docker compose logs -f         # watch requests
docker compose down            # stop + remove
```

Open http://localhost:8091.

> Stateless box (the only writes are files *you* drop via flag 3). `docker compose down
> && docker compose up -d` gives a clean slate.

## The mission — 3 flags

Format `FLAG{...}`. **Every flag is OS command injection**, escalating:

1. **Plain injection, output reflected.** `/ping?host=` runs `ping -c 1 <host>` through
   the shell and prints the result. Append your own command and read its output → `flag1`.

2. **Filter / quoting breakout.** `/lookup?domain=` runs `nslookup <domain>`, but first
   **rejects** these characters: `;` `&` `|` `` ` `` and **space**. Achieve command
   execution using none of them → `flag2`.

3. **Blind injection, out-of-band exfil.** `/monitor?target=` injects too — but the
   command's output is **thrown away** (`> /dev/null`), so you never see it. First
   *confirm* the injection with no output to look at, then move the flag to a place you
   **can** read → `flag3`.

> Note: each tool runs its shell as a different low-privileged user, and each flag file is
> readable only by its own user — so you can't shortcut flags 2 and 3 by `cat`-ing them
> from flag 1's endpoint. Solve each on its own.

## How to think about it

- **Where does input meet a shell?** Any separator ends the intended command and starts
  yours: `;`, `|`, `&&`, `||`, a newline, `$(...)`, backticks.
- **Blacklists leak (flag 2).** If spaces are banned, `${IFS}` and brace-expansion
  `{cat,/etc/hostname}` produce whitespace without a space character. If `;`/`|`/`&` are
  banned, a **newline** (`%0a` in a URL) or command substitution `$(...)` still chains.
- **Blind ≠ safe (flag 3).** No output doesn't mean no execution. Prove it with a
  **time delay** (`sleep 5` — did the response hang?). Then exfiltrate through a side
  channel: write the flag somewhere the web app will hand back to you, or beacon it out.
  What can the monitor's worker write that you can then request over HTTP?

## Tooling

- **Browser** for quick GETs; **`curl`** to control encoding precisely (URL-encode `;`
  as `%3B`, space as `%20`, newline as `%0a`).
- **Burp** (8080) repeater to iterate payloads.
- `curl -G --data-urlencode 'host=...'` encodes tricky payloads for you.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
