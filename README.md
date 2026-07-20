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
| 01 | [SecureVault](ctfs/web-beginner-01/) | Web | Beginner | ✅ solved |
| 02 | [OrgHub](ctfs/web-intermediate-02/) | Web | Intermediate | ✅ solved |
| 03 | [PostPilot](ctfs/web-advanced-03/) | Web | Advanced | ✅ solved |
| 04 | [LinkPeek](ctfs/web-advanced-04/) | Web | Advanced | ✅ solved |
| 05 | [Sentry](ctfs/net-intermediate-05/) | Network / Linux | Intermediate | ✅ solved |
| 06 | [Relay](ctfs/net-intermediate-06/) | Network / Linux | Intermediate+ | ✅ solved |
| 07 | [Forge](ctfs/net-advanced-07/) | Network / Linux | Advanced | ✅ solved |
| 08 | [Keyring](ctfs/net-advanced-08/) | Network / Linux | Advanced | ✅ solved |
| 09 | [Bookworm](ctfs/web-intermediate-09/) | Web | Intermediate | ✅ solved |
| 10 | [Postboard](ctfs/web-intermediate-10/) | Web | Intermediate | ✅ solved |
| 11 | [Reviewly](ctfs/web-intermediate-11/) | Web | Intermediate | ✅ solved |
| 12 | [Ledgr](ctfs/web-intermediate-12/) | Web | Intermediate | ✅ solved |
| 13 | [Sesame](ctfs/web-intermediate-13/) | Web | Intermediate | ✅ solved |
| 14 | [NetProbe](ctfs/web-intermediate-14/) | Web | Intermediate | ✅ solved |
| 15 | [Mailroom](ctfs/web-intermediate-15/) | Web | Intermediate | ✅ solved |
| 16 | [Cogwheel CI](ctfs/web-intermediate-16/) | Web | Intermediate | ✅ solved |
| 17 | [Loglet](ctfs/web-intermediate-17/) | Web | Intermediate | ✅ solved |

Outside challenges (boxes from elsewhere) live under
[`ctfs/outside-challenges/`](ctfs/outside-challenges/).

## 🏃 Running a CTF

Each CTF folder has its own README. In general (Docker Desktop):

```bash
cd ctfs/<challenge>
docker compose up -d       # start → http://localhost:8081
docker compose stop        # stop
docker compose down        # remove / reset
```

> ⚠️ Everything here targets local, self-owned lab machines only.

> 🔌 **Port convention:** CTF apps publish on host port **8081** (`8081:5000` in
> `docker-compose.yml`). Port **8080** is reserved for Burp Suite's default proxy
> listener, so the two never collide when proxying lab traffic.

---
*Notes are a snapshot copied from my Obsidian vault — re-copy from `red-team-guide/`'s
source when I update the vault.*
