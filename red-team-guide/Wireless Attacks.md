---
tags: [red-team, wireless, wifi]
---

# 📶 Wireless Attacks

← back to [[Red Team Ideology]]

```mermaid
flowchart TD
    W([📶 WiFi Target]) --> MON[Interface → monitor mode<br/>airmon-ng start wlan0]
    MON --> RECON[Scan APs &amp; clients<br/>airodump-ng]
    RECON --> E{Encryption?}

    E -->|Open| OPEN[Open network]
    E -->|WEP| WEP[WEP — legacy]
    E -->|WPA2-PSK| WPA2[WPA2 Personal]
    E -->|WPA2-Enterprise| ENT[WPA2 Enterprise]
    E -->|WPS enabled| WPS[WPS]

    OPEN --> OPENp[Evil twin, MITM,<br/>captive portal phish]
    WEP --> WEPp[IV capture →<br/>aircrack-ng instant]
    WPA2 --> WPA2p[Deauth → capture handshake<br/>→ hashcat -m 22000]
    WPS --> WPSp[Reaver / Bully<br/>PIN brute or Pixie Dust]
    ENT --> ENTp[Rogue AP + hostapd-wpe<br/>→ steal MSCHAPv2 → crack]

    WPA2p --> CRACK[Crack hash → see Password note]
    ENTp --> CRACK

    classDef enc fill:#065f46,stroke:#6ee7b7,color:#fff;
    class OPEN,WEP,WPA2,ENT,WPS enc;
```

## Workflow
1. **Monitor mode** — `airmon-ng start wlan0`, kill interfering processes.
2. **Recon** — `airodump-ng` to list APs, channels, connected clients.
3. **Capture** — deauth a client (`aireplay-ng --deauth`) to force a handshake.
4. **Crack offline** — feed to `hashcat -m 22000` with a wordlist (rockyou, etc.).
5. **Beyond the key** — evil twin / rogue AP for creds; pivot onto the LAN → [[Network & Infra Attacks]].

**Tools:** `aircrack-ng` suite · `hcxdumptool`/`hcxpcapngtool` · `hostapd-wpe` · `bettercap` · `wifite`
> Needs a monitor-mode capable adapter (e.g. Alfa). Test only on your own networks / lab.
