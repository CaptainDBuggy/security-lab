---
tags: [red-team, methodology, index]
aliases: [Red Team Methodology, RT Ideology, Attack Map]
---

# 🧠 Red Team Ideology — Master Flowchart

> **How to use:** Start at the top. Identify *what kind of box / target* is in front of you, follow the branch, then open the linked domain note to drill into specific attacks. This is a living map — add nodes as you learn.

## 🎯 Where am I? (Triage the target)

```mermaid
flowchart TD
    START([🎯 New Target / Box]) --> RECON[Recon &amp; Enumerate<br/>What is it?]

    RECON --> Q{What kind of<br/>target is it?}

    Q -->|HTTP/HTTPS, login pages, APIs| WEB[🌐 Web App]
    Q -->|Open ports, services, subnets| NET[🖧 Network / Infra]
    Q -->|Domain-joined, Windows, LDAP/Kerberos| AD[🏰 Active Directory]
    Q -->|SSIDs, APs, radio| WIFI[📶 Wireless / WiFi]
    Q -->|A binary, firmware, crackme| RE[🔬 Reverse Engineering]
    Q -->|A physical device, ESP32, IoT| HW[🔌 Hardware / IoT]
    Q -->|Humans, email, phone| SE[🎭 Social Engineering]
    Q -->|Hashes, creds, logins| CRED[🔑 Password / Creds]

    WEB --> WEBN[Injection, XSS, auth,<br/>IDOR, SSRF, upload]
    NET --> NETN[Service enum, CVEs,<br/>SMB, foothold, privesc]
    AD --> ADN[Roasting, BloodHound,<br/>ACLs, PtH, DCSync]
    WIFI --> WIFIN[Handshake capture,<br/>evil twin, WPS]
    RE --> REN[Static, dynamic,<br/>pwn, patching]
    HW --> HWN[UART/JTAG, firmware,<br/>RF, ESP32]
    SE --> SEN[Phishing, vishing,<br/>pretext, BadUSB]
    CRED --> CREDN[Crack, spray,<br/>reuse, pass-the-hash]

    classDef domain fill:#1f2937,stroke:#f87171,stroke-width:2px,color:#fff;
    class WEB,NET,AD,WIFI,RE,HW,SE,CRED domain;
```

## 🗺️ The Kill Chain (mental model behind every branch)

```mermaid
flowchart LR
    A[Recon] --> B[Enumerate] --> C[Exploit / Initial Access] --> D[Privilege Escalation] --> E[Persistence] --> F[Lateral Movement] --> G[Exfil / Impact]
    style A fill:#0e7490,color:#fff
    style C fill:#b91c1c,color:#fff
    style D fill:#b91c1c,color:#fff
    style F fill:#a16207,color:#fff
    style G fill:#166534,color:#fff
```

Every domain note below maps onto this chain: you **recon → enumerate → get a foothold → escalate → move → achieve objective.**

---

## 📂 Domain Notes (drill down)

| Target | Note | You reach for it when… |
|---|---|---|
| 🌐 Web | [[Web App Attacks]] | There's a website, API, or login |
| 🖧 Network | [[Network & Infra Attacks]] | You have IPs, ports, and services |
| 🏰 AD | [[Active Directory Attacks]] | It's a Windows domain |
| 📶 WiFi | [[Wireless Attacks]] | You're attacking radio / SSIDs |
| 🔬 RE | [[Reverse Engineering]] | You have a binary or firmware |
| 🔌 Hardware | [[Hardware & IoT Attacks]] | Physical device, ESP32, embedded |
| 🎭 SocEng | [[Social Engineering]] | The target is people |
| 🔑 Creds | [[Password & Credential Attacks]] | You have hashes or need to auth |

---

## 🧰 Always-on toolbelt

- **Recon:** `nmap`, `masscan`, `amass`, `ffuf`, `gobuster`, `subfinder`
- **Web:** Burp Suite, `sqlmap`, `nikto`, `wpscan`
- **AD:** BloodHound, `impacket`, `crackmapexec`/`nxc`, `rubeus`
- **Creds:** `hashcat`, `john`, `hydra`
- **Post-ex:** `mimikatz`, `linpeas`/`winpeas`, Metasploit
- **Wireless:** `aircrack-ng`, `hcxdumptool`, `bettercap`

> ⚠️ **Rules of engagement:** everything here is for authorized testing, labs (HTB/THM/OSCP), and CTFs only. Scope first, get it in writing, stay in bounds.

*See also: [[Methodology Cheatsheet]]*
