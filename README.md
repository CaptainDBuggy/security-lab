# 🛡️ security-lab

My offensive-security learning journey — methodology notes and hands-on CTF challenges.

## 📚 Contents

| Folder | What's in it |
|---|---|
| [`red-team-guide/`](red-team-guide/) | Red Team methodology — a flowchart-driven guide that triages a target (web / network / AD / wifi / RE / hardware / social eng / creds) and drills into specific attacks. Start at **Red Team Ideology.md**. |
| [`ctfs/`](ctfs/) | Self-hosted CTF challenges I've built and solved, each in its own folder with a Dockerized app and a (spoiler-gated) `SOLUTION.md`. |

## 🧩 CTFs

| # | Name | Type | Difficulty | Status |
|---|------|------|-----------|--------|
| 01 | [SecureVault](ctfs/web-beginner-01/) | Web | Beginner | 🚧 in progress |

## 🏃 Running a CTF

Each CTF folder has its own README. In general (Docker Desktop):

```bash
cd ctfs/<challenge>
docker compose up -d       # start → http://localhost:8080
docker compose stop        # stop
docker compose down        # remove / reset
```

> ⚠️ Everything here targets local, self-owned lab machines only.

---
*Notes are a snapshot copied from my Obsidian vault — re-copy from `red-team-guide/`'s
source when I update the vault.*
