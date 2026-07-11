---
tags: [red-team, hardware, iot, esp32]
---

# 🔌 Hardware & IoT Attacks

← back to [[Red Team Ideology]]

```mermaid
flowchart TD
    H([🔌 Physical Device]) --> RECON[Open it up<br/>identify chips, ports, labels]
    RECON --> T{Attack surface?}

    T -->|Debug pads / headers| DEBUG[Hardware interfaces]
    T -->|Flash chip| FLASH[Firmware extraction]
    T -->|Radio| RADIO[RF / wireless]
    T -->|Network stack| NETIF[Network services]

    DEBUG --> D1[UART — serial console/shell]
    DEBUG --> D2[JTAG / SWD — halt CPU, dump]
    DEBUG --> D3[I2C / SPI — sniff bus]
    FLASH --> F1[Desolder / clip → read SPI flash]
    FLASH --> F2[binwalk extract → see RE note]
    RADIO --> R1[BLE — sniff, replay, GATT enum]
    RADIO --> R2[Sub-GHz — capture &amp; replay w/ SDR]
    RADIO --> R3[WiFi → see Wireless note]
    NETIF --> N1[Default creds, open telnet]
    NETIF --> N2[→ see Network note]

    classDef surf fill:#164e63,stroke:#67e8f9,color:#fff;
    class DEBUG,FLASH,RADIO,NETIF surf;
```

## Workflow
1. **Physical recon** — teardown, read chip part numbers, find test pads.
2. **Get a console** — UART is the usual quick win (`screen`/`minicom` at 115200).
3. **Dump firmware** — via bootloader, `esptool` (ESP32), or SPI flash reader.
4. **Analyze** — `binwalk` the dump, then reverse extracted binaries.
5. **RF** — capture/replay with an SDR or dedicated radio; BLE with `bettercap`/`nRF`.

**Your kit:** ESP32 (great for RF/WiFi tooling & building your own implants) · logic analyzer · USB-UART adapter · `esptool` · `binwalk`
> ESP32 note: you've got this in the lab — good for evil-portal / deauth-detector builds and learning UART/SPI hands-on.
