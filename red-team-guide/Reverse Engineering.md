---
tags: [red-team, reverse-engineering, binary]
---

# 🔬 Reverse Engineering

← back to [[Red Team Ideology]]

```mermaid
flowchart TD
    B([🔬 Binary / Firmware]) --> TRIAGE[Triage<br/>file, strings, checksec]
    TRIAGE --> T{Goal?}

    T -->|Understand behavior| STATIC[Static analysis]
    T -->|Watch it run| DYN[Dynamic analysis]
    T -->|Find a memory bug| PWN[Binary exploitation]
    T -->|Crack a check / keygen| CRACK[Crackme / patching]

    STATIC --> S1[Ghidra / IDA — decompile]
    STATIC --> S2[Map functions, xrefs]
    DYN --> D1[gdb + pwndbg / x64dbg]
    DYN --> D2[ltrace / strace, Frida]
    PWN --> P1[Buffer overflow → ret2win]
    PWN --> P2[ROP / ret2libc]
    PWN --> P3[Format string]
    PWN --> P4[Heap: UAF, tcache]
    CRACK --> C1[Patch the jump<br/>NOP / invert branch]
    CRACK --> C2[Bypass license check]

    P1 --> EXP[Build exploit → shell]
    P2 --> EXP
    P3 --> EXP
    P4 --> EXP

    classDef mode fill:#78350f,stroke:#fcd34d,color:#fff;
    class STATIC,DYN,PWN,CRACK mode;
```

## Workflow
1. **Triage** — `file`, `strings`, `checksec` (NX, PIE, canary, RELRO).
2. **Static** — load in Ghidra, find `main`, follow user-input paths.
3. **Dynamic** — run under `gdb`/pwndbg, set breakpoints, watch memory.
4. **Exploit** — mitigation-dependent: overflow → ROP if NX, leak libc if ASLR.
5. **Automate** — script the exploit with `pwntools`.

**Tools:** Ghidra · IDA · `gdb` + pwndbg/GEF · `pwntools` · `radare2`/Cutler · Frida · `binwalk` (firmware)
> Firmware from a device? Pull it apart with `binwalk`, then treat extracted binaries here. Physical extraction → [[Hardware & IoT Attacks]].
