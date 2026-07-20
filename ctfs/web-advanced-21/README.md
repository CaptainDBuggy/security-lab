# Gridlock — Advanced Web CTF (a CHAINED box)

A project issue tracker. Three **distinct vulnerability classes**:
**Mass assignment → Insecure deserialization → Second-order SQL injection.**

Two of these three techniques are new — you haven't seen them in a CTF
yet. The third requires applying a familiar concept in an unfamiliar way.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`gridlock-ctf`**. Publishes on host port **8098**.

```bash
cd ~/security-lab/ctfs/web-advanced-21
docker compose up -d --build
docker compose logs -f         # watch requests
docker compose down            # stop + remove
```

Open http://localhost:8098.

## The mission — 3 flags, in order

Format `FLAG{...}`. Each stage reveals intel for the next:

1. **Escalate your privileges at registration.** Create an account and
   look at what the API actually accepts versus what the form sends.
   APIs sometimes trust client input more than they should. → `flag1`
   is on the admin panel.

2. **Exploit the import feature.** The admin panel accepts serialized
   data for board imports. The server deserializes it using a Python
   mechanism that executes code during unpacking. Research which
   serialization format does this and how to weaponize it. → `flag2`
   in a file on disk, with a hint for flag 3.

3. **Inject SQL through stored data.** This isn't a direct injection —
   the data you control is stored safely first, then used unsafely
   later in a different query. You know the table and column names
   from flag 2. Register a new account whose username IS the payload,
   then trigger the vulnerable query from the admin panel. → `flag3`
   is in the database.

## How to think about it (no spoilers)

- **Flag 1 — watch the request.** Open DevTools Network tab when you
  register. Look at the JSON body. What fields does the server accept?
  What would happen if you added fields the form doesn't have? Think
  about what field controls access level.

- **Flag 2 — what's dangerous about Python serialization?** The import
  feature takes base64-encoded data. What Python module serializes
  objects and is famously unsafe with untrusted input? What magic
  method controls what happens during deserialization? You'll need a
  short Python script to craft the payload.

- **Flag 3 — the injection point and execution point are different.**
  The registration stores your username safely (parameterized query).
  But another query uses that stored username unsafely (string
  formatting). You need to get your payload into the database first,
  then trigger the query that uses it. The UNION technique you've used
  before works — you just need the right table and column names.

## Tooling

- **Browser + DevTools** — Network tab for intercepting registration.
- **Burp Suite** — Repeater for modifying the registration request.
- **Python** — Required for crafting the pickle payload.
- **curl** — Quick way to register with extra fields.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
