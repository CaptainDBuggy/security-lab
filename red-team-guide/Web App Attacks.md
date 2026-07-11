---
tags: [red-team, web]
---

# 🌐 Web App Attacks

← back to [[Red Team Ideology]]

```mermaid
flowchart TD
    W([🌐 Web App]) --> ENUM[Map the app<br/>dirs, params, tech stack]
    ENUM --> T{Attack surface?}

    T -->|User input reflected| XSS[Cross-Site Scripting]
    T -->|DB-backed queries| SQLI[SQL Injection]
    T -->|Login / session| AUTH[Auth &amp; Session Flaws]
    T -->|Object IDs in URL| IDOR[IDOR / BOLA]
    T -->|File upload / include| FILE[File Upload / LFI-RFI]
    T -->|Server fetches URLs| SSRF[SSRF]
    T -->|Templates render input| SSTI[Template Injection]
    T -->|OS commands built from input| CMDI[Command Injection]
    T -->|Serialized objects| DESER[Insecure Deserialization]

    XSS --> XSSp[Reflected / Stored / DOM<br/>→ cookie theft, session ride]
    SQLI --> SQLIp[Union / Blind / Error<br/>→ sqlmap, dump creds]
    AUTH --> AUTHp[Weak reset, JWT tampering,<br/>default creds, brute force]
    IDOR --> IDORp[Increment/swap IDs<br/>→ access others' data]
    FILE --> FILEp[Upload webshell,<br/>LFI→log poison→RCE]
    SSRF --> SSRFp[Hit 169.254.169.254,<br/>internal services]
    SSTI --> SSTIp["{{7*7}} → RCE"]
    CMDI --> CMDIp["; whoami → shell"]
    DESER --> DESERp[Gadget chains → RCE]

    classDef vuln fill:#7f1d1d,stroke:#fca5a5,color:#fff;
    class XSS,SQLI,AUTH,IDOR,FILE,SSRF,SSTI,CMDI,DESER vuln;
```

## Workflow
1. **Enumerate** — `ffuf`/`gobuster` dirs, `whatweb`/Wappalyzer stack, spider in Burp.
2. **Test inputs** — every param, header, cookie against the vuln classes above.
3. **Escalate** — turn a vuln into a shell (webshell, SSTI/CMDI RCE) or data (SQLi dump).
4. **Reference:** OWASP Top 10, PortSwigger Web Security Academy.

**Tools:** Burp Suite · `sqlmap` · `ffuf` · `nikto` · `wpscan` · `nuclei`
