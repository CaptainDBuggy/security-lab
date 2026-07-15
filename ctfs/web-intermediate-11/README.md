# 🛍️ Reviewly — Intermediate Web CTF (Cross-Site Scripting II)

A product-review site. Same primitive as Postboard — **cross-site scripting** — but
every flag lands in a **different injection context**, so this is fresh reps, not a
reskin: an HTML **attribute**, a stored **comment**, and a client-side
**`document.write`**.

**Authorized target: this box only.** Everything runs locally in Docker.

There's a real **moderator bot** inside the container (headless Chromium carrying the
mod's cookies) that actually reviews comments and opens reported links and *executes*
your payloads.

## Rerun-friendly (you asked for this)

State lives in memory, but you don't need to restart the container to replay:

- **Delete a single comment** — the **×** button on each review.
- **Delete all comments** / **Clear collector** — buttons in the **🧪 Lab controls**
  panel (bottom of `/reviews` and `/collector`, and on the home page).
- **Reset everything** — the **Reset lab** button (or `POST /reset`) wipes comments,
  the report queue, and the collector, then reseeds the two starter reviews.

So the loop is: land a flag → hit **Reset lab** → try a different payload → repeat.

## Run it

Compose project name: **`reviewly-ctf`**. Publishes on host port **8088**
(Burp keeps its default 8080, so you can proxy freely).

**Docker Desktop GUI:** Containers → **reviewly-ctf** → ▶ / ⏹.

**Or the terminal:**

```bash
cd ~/security-lab/ctfs/web-intermediate-11
docker compose up -d --build   # start (first build is slow — it pulls the Chromium image)
docker compose logs -f         # watch server + bot logs
docker compose down            # remove entirely (also resets state)
```

Open http://localhost:8088.

## The mission — 3 flags

Format `FLAG{...}`. **Every flag is XSS**, but the *context* changes each time — that's
the drill.

1. **Reflected XSS — attribute breakout.** `/search?q=` reflects your input **inside a
   double-quoted HTML attribute** (`<input value="...">`). A bare `<script>` is inert
   in that position — you have to **break out of the attribute first** (close the quote
   and the tag) before your own markup counts. Then it's the Postboard move: report the
   crafted link, and steal the moderator's **non-httpOnly** `moderator_token` cookie to
   your collector → `flag1`.

2. **Stored XSS — comments.** `/reviews` renders each review's name + body unescaped,
   and the moderator auto-reviews new ones. The mod's session cookie (`sid`) **is**
   httpOnly — you can't steal it — so **ride** it: from inside their browser,
   `fetch('/admin')` (a page you get `403` on) and exfiltrate its contents → `flag2`.

3. **DOM-based XSS — `document.write`.** `/share` reads `location.hash` and writes it
   into the page with **`document.write()`**, entirely client-side. Key difference from
   Postboard's `innerHTML` sink: `document.write` **will** execute a `<script>` you
   inject. Achieve execution and call the page's guarded `reveal()` → `flag3`. (Solve
   this one entirely in your own DevTools — no moderator needed.)

## How to think about it (context is everything)

- **Prove execution first**, then wire up delivery + exfil.
- **Attribute context:** you're already *inside* `value="..."`. Your job is to escape
  it — think `">` to close the value and the tag, then add your own element/handler.
  (What runs on an element that never loads, or one that grabs focus?)
- **Stored:** the victim comes to you; httpOnly blocks theft but not `fetch` — same
  origin sends the cookie automatically.
- **DOM / `document.write`:** the hash never reaches the server. Because `document.write`
  runs scripts, the payload can be more direct than the `innerHTML` case was.
- **Encoding gotcha (carried over):** in a URL query string, `+` decodes to a space and
  breaks your JS. Use `%2B`, or dodge it with a template literal `` `...${...}` `` — no
  `+` to mangle.

## Tooling

- **Browser + DevTools** — primary tool; you're writing/debugging JS.
- **Burp** (8080) or `curl` to craft the report + review requests.
- Keep `/collector` open in a tab and `docker compose logs -f` running to watch the bot.

## Reset / stop

```bash
# in-app:  Reset lab button, or:
curl -s -X POST http://localhost:8088/reset -o /dev/null
# container:
docker compose down     # full reset
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
