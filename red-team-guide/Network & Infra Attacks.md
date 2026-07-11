---
tags: [red-team, network]
---

# 🖧 Network & Infra Attacks

← back to [[Red Team Ideology]]

```mermaid
flowchart TD
    N([🖧 Network / Host]) --> SCAN[Scan &amp; enumerate<br/>nmap -sV -sC -p-]
    SCAN --> S{Open service?}

    S -->|SMB 139/445| SMB[SMB]
    S -->|SSH 22| SSH[SSH]
    S -->|Web 80/443| WEBSVC[Web → see Web App note]
    S -->|FTP 21| FTP[FTP]
    S -->|RDP 3389| RDP[RDP]
    S -->|SNMP 161| SNMP[SNMP]
    S -->|DB 3306/1433/5432| DB[Databases]
    S -->|Unusual / versioned| CVE[Service-specific CVE]

    SMB --> SMBp[Null session, enum shares,<br/>EternalBlue, cred spray]
    SSH --> SSHp[Weak/reused creds,<br/>key theft, brute w/ hydra]
    FTP --> FTPp[Anon login, read/write,<br/>plaintext creds]
    RDP --> RDPp[Cred spray, BlueKeep,<br/>session hijack]
    SNMP --> SNMPp[public string →<br/>walk config, creds]
    DB --> DBp[Default creds, UDF RCE,<br/>xp_cmdshell]
    CVE --> CVEp[searchsploit version,<br/>Metasploit module]

    CVE --> FOOT[⚙️ Got a shell?]
    SMBp --> FOOT
    FOOT --> PRIV[Privilege Escalation<br/>linpeas / winpeas]
    PRIV --> ROOT([👑 root / SYSTEM])

    classDef svc fill:#1e3a8a,stroke:#93c5fd,color:#fff;
    class SMB,SSH,FTP,RDP,SNMP,DB,CVE svc;
```

## Workflow
1. **Scan** — `nmap -sC -sV -p-` then targeted scripts.
2. **Enumerate each service** — banners, versions, default creds, anonymous access.
3. **Exploit** — `searchsploit <service version>`, public PoC, or Metasploit.
4. **Foothold → PrivEsc** — run `linpeas`/`winpeas`, check sudo, SUID, cron, kernel.
5. **Escalate creds:** see [[Password & Credential Attacks]]; if domain-joined → [[Active Directory Attacks]].

**Tools:** `nmap` · `crackmapexec`/`nxc` · `enum4linux-ng` · Metasploit · `searchsploit`
