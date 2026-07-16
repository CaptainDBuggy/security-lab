# 📬 Mailroom — Intermediate Web CTF (a CHAINED box)

An internal parcel & document portal for the ops team. Unlike the earlier boxes — where
each flag drilled one primitive in isolation — **Mailroom is a single attack path**. Four
different web bugs, each one the key that unlocks the door to the next. You cannot reach
flag 4 without walking through 1 → 2 → 3.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`mailroom-ctf`**. Publishes on host port **8092**
(Burp keeps its default 8080; 8081–8091 are earlier CTFs).

```bash
cd ~/security-lab/ctfs/web-intermediate-15
docker compose up -d --build
docker compose logs -f         # watch requests
docker compose down            # stop + remove (fresh DB + wiped uploads next boot)
```

Open http://localhost:8092.

> The user DB and upload spool are rebuilt on every boot. `docker compose down &&
> docker compose up -d` gives a clean slate if you wedge something.

## The mission — 4 flags, in order

Format `FLAG{...}`. Each stage hands you what you need for the next:

1. **Get in.** You have **no credentials** (IT never gave you any — that's the point). The
   sign-in form talks to a JSON API backed by a document database. Make the login succeed
   anyway. → `flag1` on your dashboard.

2. **Become staff.** Your account is a plain `user`; the *sorting area* is staff-only.
   There's a perfectly innocent "update your display name" feature… that saves a bit more
   than a display name if you ask it to. Promote yourself. → `flag2` in the staff area.

3. **Break the uploader.** The staff uploader insists it's *images only*. Prove that's a
   lie the client tells and the server never enforces. → `flag3`.

4. **Read what you shouldn't.** Staff attachments are served *by name* from the label
   store. The store has a neighbour directory it was never meant to reach. Get its
   contents. → `flag4`.

## How to think about it

- **Recon first, and it's in the JS.** There is no `robots.txt` gift here. The API
  endpoints and the exact field names each one expects live in the inline `<script>` on
  each page — read the page source / your Burp history like you'd read an SPA's bundle.

- **Flag 1 — the database speaks in objects, not just strings.** When an app matches
  `{username: X, password: Y}` and drops your input straight in, ask: *what if X or Y
  isn't a string?* A query **operator** in place of a value changes the question the
  database is answering. (`$ne`, `$gt`, `$regex`, `$in` are the usual suspects.) You're
  sending JSON — you control the *types*, not just the values.

- **Flag 2 — the form sends one field; the endpoint accepts all of them.** Watch the
  actual request the "save profile" button makes, then ask what *other* fields your user
  record has that the server would happily `$set` if you included them. Mass assignment is
  about the gap between the UI's fields and the model's fields.

- **Flag 3 — "images only" where?** Client-side labels aren't validation. Send bytes that
  are obviously not an image and see whether the server cares. `curl` doesn't run the
  page's JavaScript.

- **Flag 4 — "by name" is a filesystem path.** If `name` becomes part of a path with no
  cleaning, `../` is a valid part of a name. Where does the flag file sit *relative to* the
  upload folder? (The upload response in step 3 tells you the exact route and parameter.)

## Tooling

- **Browser + DevTools** to read the inline JS and the requests each button fires.
- **`curl`** for full control of body *types* — `-H 'Content-Type: application/json'
  -d '{"username":...,"password":{...}}'` lets you send an object where the app expects a
  string. Keep the session cookie with `-c jar -b jar`.
- **Burp** (8080) repeater to iterate the login payload and the profile patch.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
