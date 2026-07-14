# 🚩 OrgHub — SOLUTION (SPOILERS)

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

## Flag 1 — IDOR / horizontal access (`FLAG{1d0r_0bj3ct_l3v3l_pwn3d}`)

- Log in as `alice` / `Password1!`. Your dashboard links to `/account?id=1`.
- The `id` is a direct object reference with **no ownership check**. Change it:
  `GET /account?id=2` → Bob's account, whose private note holds **Flag 1**.
- Reading `/account?id=3` (admin) also leaks the hint pointing at `/admin/users`.

**Lesson:** every object lookup driven by a client-supplied ID must verify the object
belongs to (or is visible to) the caller. Use unguessable IDs *and* server-side authz.

## Flag 2 — Broken function-level authz / forced browsing (`FLAG{f0rc3d_br0ws1ng_h1dd3n_n0t_saf3}`)

- `GET /admin` correctly denies non-admins (role checked from the DB).
- But `GET /admin/users` has **no role check at all** — it was just never linked in
  the user UI. Any logged-in user who requests the URL gets the staff directory and
  the **Flag 2** audit token.
- Discovery paths: the IDOR read of admin's note ("console lives at /admin/users"),
  `robots.txt` disallowing `/admin`, or plain endpoint guessing.

**Lesson:** "hidden" is not "protected." Every sensitive function needs its own
server-side authorization check — you can't rely on the UI not linking it.

## Flag 3 — Mass assignment / vertical privilege escalation (`FLAG{m4ss_4ss1gnm3nt_r0l3_pwn}`)

- The profile form only submits `full_name`, but `/account/update` blindly writes
  **any** POST field matching a DB column (mass assignment).
- Intercept the "Save" request in Burp (or use curl) and add `role=admin`:
  ```
  POST /account/update
  full_name=Alice+Adams&role=admin
  ```
  ```
  curl -b "session=<your-cookie>" -d "full_name=x&role=admin" http://localhost:8081/account/update
  ```
- Your DB role is now `admin`. Visit `/admin` → **Flag 3**.
- Note: you can't shortcut this by editing the cookie — the session is signed, and
  `/admin` reads role from the DB, so you must actually persist the change server-side.

**Lesson:** never bind client-controlled input directly to model fields. Whitelist the
fields a user may set (here: only `full_name`); never let `role`/`is_admin` through.

---

### Full flag list
1. `FLAG{1d0r_0bj3ct_l3v3l_pwn3d}`
2. `FLAG{f0rc3d_br0ws1ng_h1dd3n_n0t_saf3}`
3. `FLAG{m4ss_4ss1gnm3nt_r0l3_pwn}`
