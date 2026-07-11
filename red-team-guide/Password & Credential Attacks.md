---
tags: [red-team, credentials, passwords]
---

# 🔑 Password & Credential Attacks

← back to [[Red Team Ideology]]

```mermaid
flowchart TD
    C([🔑 Creds / Hashes]) --> Q{What do I have?}

    Q -->|A hash| HASH[Offline cracking]
    Q -->|A live login| ONLINE[Online attack]
    Q -->|One valid cred| REUSE[Spray &amp; reuse]
    Q -->|A session/ticket| PASS[Pass-the-*]

    HASH --> H1[Identify: hashid / hashcat --example]
    H1 --> H2[hashcat / john<br/>wordlist + rules]
    H2 --> H3[rockyou → mask → hybrid]

    ONLINE --> O1[hydra / medusa<br/>SSH, FTP, RDP, HTTP]
    ONLINE --> O2[Watch lockout policy!]

    REUSE --> RE1[Password spray<br/>1 pass × many users]
    REUSE --> RE2[Cred stuffing<br/>known breach combos]

    PASS --> PA1[Pass-the-Hash]
    PASS --> PA2[Pass-the-Ticket]
    PASS --> PA3[Overpass-the-Hash]

    H3 --> WIN([🔓 Valid credential])
    RE1 --> WIN
    PA1 --> WIN
    WIN --> USE[Reuse everywhere →<br/>see Network / AD notes]

    classDef m fill:#7c2d12,stroke:#fdba74,color:#fff;
    class HASH,ONLINE,REUSE,PASS m;
```

## Workflow
1. **Identify** the hash type first (`hashid`, `hashcat --example-hashes`).
2. **Crack offline** — always prefer this over noisy online brute force.
   - `hashcat -m <mode> hash.txt rockyou.txt -r rules/best64.rule`
3. **Online** only when you must — respect lockout thresholds; spray > brute.
4. **Pass-the-* ** — often you don't need to crack; the hash/ticket *is* the key (AD).
5. **Reuse** — humans reuse passwords; try each win against every service.

**Tools:** `hashcat` · `john` · `hydra`/`medusa` · `hashid` · `impacket` (PtH/PtT) · CeWL/Mentalist (custom wordlists)
**Wordlists:** rockyou, SecLists, custom from OSINT.
