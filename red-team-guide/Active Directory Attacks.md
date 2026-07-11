---
tags: [red-team, active-directory, windows]
---

# 🏰 Active Directory Attacks

← back to [[Red Team Ideology]]

```mermaid
flowchart TD
    AD([🏰 AD Domain]) --> STAGE{What do I have?}

    STAGE -->|No creds yet| NOCRED[Unauthenticated]
    STAGE -->|A valid user| USER[Authenticated user]
    STAGE -->|Local admin on a box| LADMIN[Local admin]
    STAGE -->|Domain admin| DA([👑 Domain Admin])

    NOCRED --> N1[Responder / LLMNR poisoning]
    NOCRED --> N2[AS-REP roasting<br/>no-preauth users]
    NOCRED --> N3[Anonymous LDAP / SMB enum]
    NOCRED --> N4[Password spray common creds]

    USER --> U1[BloodHound — map paths]
    USER --> U2[Kerberoasting<br/>service accounts → crack]
    USER --> U3[ACL abuse<br/>GenericAll, WriteDACL]
    USER --> U4[Find creds in shares / GPP]

    LADMIN --> L1[Mimikatz — dump LSASS]
    LADMIN --> L2[Pass-the-Hash / OverPass]
    LADMIN --> L3[Token impersonation]
    LADMIN --> L4[DCSync if rights allow]

    N1 --> CRACK[Crack hash →]
    N2 --> CRACK
    U2 --> CRACK
    CRACK --> USER

    L4 --> DA
    U3 --> LADMIN

    classDef stage fill:#4c1d95,stroke:#c4b5fd,color:#fff;
    class NOCRED,USER,LADMIN stage;
```

## The AD loop
**Enumerate → get a credential → crack/relay it → escalate rights → repeat until DA.**

1. **Foothold** — poison with Responder, or spray/AS-REP roast for a first hash.
2. **Map** — run BloodHound (`nxc`/`bloodhound-python`), find shortest path to DA.
3. **Escalate** — Kerberoast, ACL abuse, or dump creds from a box you own.
4. **Domain takeover** — DCSync → `krbtgt` hash → Golden Ticket → persistence.

**Tools:** BloodHound · `impacket` (secretsdump, GetUserSPNs) · `nxc`/`crackmapexec` · Rubeus · Mimikatz · Responder
Feeds into → [[Password & Credential Attacks]]
