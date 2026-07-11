# 🚩 SecureVault — SOLUTION (SPOILERS)

> ⛔⛔⛔ **STOP.** This file contains the full answers to all three flags.
> If you're still solving it, close this now. Kept in the repo as a personal
> reference / write-up, not to read while playing.
>
> (Scroll past this wall of warning only if you really mean to.)
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
>
> .
>
> .
>
> .
>
> .

---

## Flag 1 — Recon (`FLAG{r3c0n_r0b0ts_n3v3r_li3}`)

- The landing page (`/`) has an HTML comment (View Source) hinting that `robots.txt`
  leaks staging paths.
- `GET /robots.txt` → `Disallow: /dev-notes`.
- `GET /dev-notes` → internal dev notes page displays **Flag 1**, plus hints for the
  next two stages (guest/guest account; admin panel trusts the `role` cookie; login
  query is unsafe).

**Lesson:** `robots.txt` and page source routinely disclose hidden endpoints. Always
enumerate them first.

## Flag 2 — Client-side trust / cookie tampering (`FLAG{c00k13s_ar3_cl13nt_s1d3}`)

- Log in as `guest` / `guest`. The server sets a plain (unsigned) cookie `role=user`.
- Visit `/admin` → "Access denied. Your role is: user".
- Edit the cookie value `role` from `user` to `admin` (DevTools → Application →
  Cookies, or `curl --cookie "role=admin" http://localhost:8081/admin`).
- Reload `/admin` → **Flag 2**.

**Lesson:** never trust client-controlled data (cookies/headers/hidden fields) for
authorization. The server must decide, using a signed/opaque session.

## Flag 3 — SQL injection (`FLAG{sql_1nj3ct10n_th3_cl4ss1c}`)

- The login query is string-built:
  `SELECT ... FROM users WHERE username='<u>' AND password='<p>'`.
- Log in with username `admin'-- ` (note trailing space) and any password. The `--`
  comments out the password check, authenticating you as **admin**.
- The signed session is now `admin`, so `/dashboard` renders the admin's private
  note, which contains **Flag 3**.
- (You cannot forge this via the cookie — the session is signed, so SQLi is required.)

**Lesson:** use parameterized queries / prepared statements. Never concatenate user
input into SQL.

---

### Full flag list
1. `FLAG{r3c0n_r0b0ts_n3v3r_li3}`
2. `FLAG{c00k13s_ar3_cl13nt_s1d3}`
3. `FLAG{sql_1nj3ct10n_th3_cl4ss1c}`
