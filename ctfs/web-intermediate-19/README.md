# Vaultline — Intermediate Web CTF (a CHAINED box)

A team secrets management dashboard. Three **distinct vulnerability
classes**, each unlocking the next: **Cookie tampering → SSRF → SSRF
protocol smuggling.**

Each flag requires a different technique. Recon and DevTools are your
best friends.

**Authorized target: this box only.** Everything runs locally in Docker.

## Run it

Compose project name: **`vaultline-ctf`**. Publishes on host port **8096**.

```bash
cd ~/security-lab/ctfs/web-intermediate-19
docker compose up -d --build
docker compose logs -f         # watch requests
docker compose down            # stop + remove
```

Open http://localhost:8096.

## The mission — 3 flags, in order

Format `FLAG{...}`. Each stage reveals intel for the next:

1. **Bypass access control.** The app has a demo account. Log in and
   look at how your session is stored — it's not on the server. The
   format is recognizable. Can you give yourself a different role?
   → `flag1` is on the admin panel.

2. **Reach an internal service.** The admin panel has a webhook tester
   that makes server-side requests to a URL you provide. There's a
   service running inside the container that isn't exposed externally.
   Find its address and use the webhook tester to talk to it.
   → `flag2` and a hint about what to read next.

3. **Read a local file.** The webhook fetcher is too permissive about
   what kinds of URLs it accepts. HTTP isn't the only scheme.
   → `flag3` from a file on disk.

## How to think about it (no spoilers)

- **Start with the cookie.** After logging in, check DevTools →
  Application → Cookies. The value looks encoded. What encoding uses
  A-Z, a-z, 0-9, +, /, and = padding?

- **Flag 1 — what's in the cookie?** Decode it. You'll see a JSON
  structure with fields the server trusts blindly. Modify what matters,
  re-encode, and replace the cookie.

- **Flag 2 — where's the internal service?** Once you're on the admin
  page, the page makes API calls in the background. Watch the Network
  tab — one response has more information than what's rendered on screen.
  The webhook tester is your proxy into the internal network.

- **Flag 3 — what schemes does a URL support?** HTTP fetches web pages.
  What other URI schemes can fetch content? Think about what you'd use
  in an XXE payload.

## Tooling

- **Browser + DevTools** — Application tab for cookies, Network tab for
  API responses. Both are critical.
- **Base64 decoder** — `echo '<value>' | base64 -d` in terminal, or
  DevTools console: `atob('<value>')`.
- **Burp Suite** — Repeater for webhook requests.

## Stop / remove

```bash
docker compose down     # stop + remove
docker compose stop     # pause, keep the built image
docker compose start    # resume
```

> ⚠️ Everything here targets a local, self-owned lab box only.
