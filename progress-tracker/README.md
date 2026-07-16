# 📊 CTF Progress Tracker

A small Electron desktop app that tracks progress through the `security-lab` CTFs:
challenges solved, hints used per CTF, and which exploit primitives you've trained.

## Run it

```bash
cd ~/security-lab/progress-tracker
npm install      # first time only (downloads the Electron runtime)
npm start
```

## What it shows

- **Stat row** — total CTFs, solved, open, distinct exploits *trained* (primitives that
  appear in at least one solved box), total hints used, and average hints per solved box.
- **Exploits trained** — a bar per primitive (SQLi, XSS, SSRF, IDOR, JWT, …) with a
  `solved/total` count, so you can see coverage and where the gaps are.
- **Challenges** — every box with its type, difficulty, exploit tags, a hint counter
  (`−`/`+`), and a status toggle (⬜ open / ✅ solved).

## Editing

- **`+ Add CTF`** — add a new challenge (name, type, difficulty, comma-separated exploits).
- Click **± on Hints** or the **status pill** to update a row; changes save immediately.
- **Reset** — restore the seeded data (`seed.json`).

## Data

- Seed data lives in `seed.json` (the 14 CTFs as of this build).
- Your live/edited data is stored outside the repo, in Electron's per-user data dir:
  `~/Library/Application Support/ctf-progress-tracker/progress.json`.
  Delete that file (or hit **Reset**) to start over from the seed.

> `node_modules/` is git-ignored. This is a local tool; nothing leaves your machine.
