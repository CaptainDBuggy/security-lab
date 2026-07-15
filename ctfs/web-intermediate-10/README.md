# 📌 Postboard — Intermediate Web CTF (Cross-Site Scripting)

A community notice board with a single classic weakness threaded through it:
**cross-site scripting**. One primitive, drilled three ways — reflected, stored, and
DOM-based — so you stop *reading* for the sink and start *seeing* it.

**Authorized target: this box only.** Everything runs locally in Docker.

There's a real **moderator bot** inside the container: a headless Chromium that carries
the moderator's cookies and actually reviews the board and opens reported links. It
*executes* your payloads — this is not a filter pretending to be a victim. Land real
JavaScript in its session and you win.

## Run it

Compose project name: **`postboard-ctf`**. Publishes on host port **8087**
(Burp keeps its default 8080, so you can proxy freely).

**Docker Desktop GUI:** Containers → **postboard-ctf** → ▶ / ⏹.

**Or the terminal:**

```bash
cd ~/security-lab/ctfs/web-intermediate-10
docker compose up -d --build   # start (first build is slow — it downloads Chromium)
docker compose logs -f         # watch server + bot logs
docker compose down            # remove entirely (fresh reset next 'up')
```

Open http://localhost:8087.

> ⚠️ **State note:** notes, the report queue, and your collector live in memory and
> reset on every container restart. `down` then `up` for a clean slate.
> The first `up` is slow (Chromium download); later starts are fast.

## The mission — 3 flags

Format `FLAG{...}`, increasing difficulty. **Every flag is XSS** — the same primitive
in three escalating flavours. That repetition is the point.

1. **Reflected XSS → cookie theft.** `/search?q=` drops your input into the page with
   no encoding. On its own that's just an alert in *your* browser — so **report a
   crafted `/search?q=...` link to the moderator** (`/report`). Their browser opens it
   while logged in. The mod's `moderator_token` cookie is **not** httpOnly, so JS can
   read it. Steal it to your **collector** (`/collect?c=...`, view at `/collector`) and
   read `flag1` off the cookie.

2. **Stored XSS → session riding.** `/board` renders every note's name and message
   unescaped, and the moderator auto-reviews new notes. Post a payload that fires in
   *their* session. The mod's session cookie (`sid`) **is** httpOnly — you can't steal
   it — but you don't need to: from inside their browser, `fetch('/admin')` returns a
   moderators-only page holding `flag2`. Exfiltrate that page's contents to your
   collector.

3. **DOM-based XSS.** `/widget` reads `location.hash` and writes it straight into
   `innerHTML` — entirely client-side, no server round-trip. `<script>` won't run from
   `innerHTML`, so reach for a mark that fires on insertion. Achieve execution in the
   page and call the page's guarded `reveal()` to print `flag3`. (This one you can
   solve entirely in your own browser — no moderator needed.)

## How to think about it (the XSS ladder)

- **Prove execution first.** Before stealing anything, confirm the sink runs your code.
  A payload that pops `alert(document.domain)` (or writes to the page) is your signal.
  Only then wire up delivery + exfil.
- **Reflected** is server-echoed HTML — a `<script>` you inject in `q` runs on page
  load. The trick isn't the payload, it's **delivery**: it has to run in the *victim's*
  browser, which is what `/report` is for. Then exfil: `document.cookie` →
  `new Image().src='/collect?c='+encodeURIComponent(document.cookie)`.
- **Stored** persists, so the victim comes to *you* — no report needed, the mod reviews
  the board on a timer. httpOnly blocks cookie theft but **not** the session: use
  `fetch()` (same-origin sends the cookie for you) to read `/admin`, then beacon the
  response text to `/collect`.
- **DOM** never touches the server sink. `innerHTML` won't execute a bare `<script>` —
  use something that fires on parse/insert (think `<img>`/`<svg>` error handlers). Once
  you have execution, `reveal()` is already defined on the page; just call it and read
  its return.

## Tooling

- **Browser + DevTools** — your primary tool here; you're writing and debugging JS.
- **Burp** (proxy on 8080) to craft/replay the report + post requests, or plain `curl`
  to submit notes and reports.
- Watch `docker compose logs -f` to see the bot working, and keep `/collector` open in
  a tab to catch what your payloads exfiltrate.

## Reset / stop

```bash
docker compose down     # full reset (clears notes, queue, collector)
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
