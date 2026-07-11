---
tags: [red-team, social-engineering, phishing]
---

# 🎭 Social Engineering

← back to [[Red Team Ideology]]

```mermaid
flowchart TD
    S([🎭 Target = People]) --> OSINT[OSINT<br/>names, emails, tech, org chart]
    OSINT --> V{Vector?}

    V -->|Email| PHISH[Phishing]
    V -->|Phone| VISH[Vishing]
    V -->|SMS| SMISH[Smishing]
    V -->|In person| PHYS[Physical / pretext]
    V -->|USB drop| MEDIA[Malicious media]

    PHISH --> P1[Credential harvest page]
    PHISH --> P2[Malicious attachment / macro]
    PHISH --> P3[OAuth consent phishing]
    VISH --> V1[Impersonate IT / helpdesk]
    PHYS --> PH1[Tailgating, badge clone]
    PHYS --> PH2[Drop rogue device on LAN]
    MEDIA --> M1[BadUSB / Rubber Ducky]

    P1 --> CAPTURED[Captured creds →]
    P2 --> SHELL[Payload → C2 callback]
    M1 --> SHELL
    PH2 --> SHELL
    CAPTURED --> LOGIN[→ see Password note]
    SHELL --> PIVOT[→ see Network / AD notes]

    classDef vec fill:#831843,stroke:#f9a8d4,color:#fff;
    class PHISH,VISH,SMISH,PHYS,MEDIA vec;
```

## Workflow
1. **OSINT** — harvest emails/naming convention (`hunter.io`, LinkedIn), tech stack, targets.
2. **Pretext** — build a believable story tied to something real (invoice, IT ticket, delivery).
3. **Deliver** — cred-harvest clone, macro doc, or QR/OAuth lure via evilginx/GoPhish.
4. **Capture → pivot** — creds feed auth attacks; payloads give a C2 foothold.

**Tools:** GoPhish · evilginx2 · SET · `theHarvester` · Maltego · Flipper/Rubber Ducky (physical)
> Only within an authorized engagement with explicit written scope. Human-targeted testing has strict legal/ethical lines — respect them.
