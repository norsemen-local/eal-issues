# EAL Demo — Case 5: Covert Channels & Data Exfiltration

An attacker moves data and pivots over **non-web protocols** — anonymous/brute
FTP, SSH to uncommon servers (relay + downgrade), and ICMP tunneling. The Palo
Alto NGFW logs the FTP/SSH/ICMP traffic as **EAL logs** and Cortex XSIAM/XDR
raises the matching analytics alerts. Several of these are **FTP/SSH-EAL-only**
detectors (no XDR-agent equivalent), so they show cleanly as firewall-sourced.

> One of five demo cases, each with a **different** EAL-alert set (see
> `../README-cases.md`). Uses only native tooling (.NET FtpWebRequest, TcpClient,
> ICMP ping) — no third-party clients required.

---

## 1. Attack flow → EAL alerts

```
   ATTACKER ──FTP/SSH/ICMP──▶ PALO ALTO NGFW ──EAL logs──▶ Cortex XSIAM/XDR
     (1) FTP anon ─▶ (2) FTP brute ─▶ (3) SSH uncommon ─▶ (4) SSH downgrade ─▶ (5) ICMP tunnel
```

| # | Stage (ATT&CK tactic) | What the script does | Enabled EAL alert | Rule id | Technique |
|---|----------------------|----------------------|-------------------|---------|-----------|
| 1 | **INITIAL ACCESS** (TA0001) | FTP login with anonymous / default creds | **FTP Connection Using an Anonymous Login or Default Credentials** | `68d806a3` | T1110 · T1078 |
| 2 | **Credential Access** (TA0006) | Many rapid FTP logins (brute force) | **Multiple Suspicious FTP Login Attempts** (+ rare FTP user `df8fa99b`) | `91db0f65` | T1110 |
| 3 | **Credential Access** (TA0006) | Connects to several uncommon SSH servers | **Multiple uncommon SSH Servers with the same Server host key** (+ SSH session `18f84dd7`) | `f154d651` | T1557 |
| 4 | **Defense Evasion / LM** (TA0005/TA0008) | Announces legacy SSH-1.5/1.99 client banner | **Suspicious SSH Downgrade** (+ Unusual SSH Activity `f1545c54`) | `f154f3c5` | T1021 · T1562.010 |
| 5 | **Command & Control** (TA0011) | Oversized + multi-host + broadcast ICMP | **Suspicious ICMP packet** (+ echo-to-multiple `09f9a9a7`, smurf `72694178`) | `f3389ebd` | T1572 |
| 6 | **Exfiltration** (TA0010) | Large file copy to a rarely-used SMB share | **Rare file transfer over SMB protocol** | `045e06dd` | T1570 |

---

## 2. Prerequisites

| Component | Requirement |
|-----------|-------------|
| Attacker host | Windows, PowerShell 5.1+. No admin needed (except a raw-ICMP tool for the exact stage-5 packet). |
| FTP server | A lab FTP server reachable through the firewall (`FtpServer`). |
| SSH servers | 2+ lab SSH servers (`SshServers`). For stage 3, arrange them to **share a host key** (e.g. cloned VMs) to trigger the detector. |
| ICMP target | Any host reachable via ICMP through the firewall. |
| NGFW | Rule covering the host, **EAL enabled**, log forwarding to Cortex. FTP/SSH/ICMP must traverse the firewall. |
| Cortex | XSIAM/XDR ingesting the firewall EAL logs. |

---

## 3. Run it

**Double-click `Start-Demo.cmd`** → **[1] Configure** (FTP/SSH/ICMP targets) →
**[2] Preflight → [3] Dry run → [4] Run**. Or:

```powershell
cd D:\PANW\eal-demo\case-5
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\00-preflight.ps1
.\scripts\Run-All.ps1 -DryRun
.\scripts\Run-All.ps1 -PauseBetween
```

Rejected FTP logins and SSH resets are **expected** — the connection attempt is
the firewall-observable signal; the scripts log and continue.

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 (IA) | FTP Connection Using an Anonymous Login or Default Credentials | `68d806a3` | anonymous/default login to FTP server |
| 2 | Multiple Suspicious FTP Login Attempts | `91db0f65` | many FTP logins in a short window |
| 3 | Multiple uncommon SSH Servers with the same Server host key | `f154d651` | connections to several SSH servers sharing a key |
| 4 | Suspicious SSH Downgrade | `f154f3c5` | SSH-1.5/1.99 client version to server |
| 5 | Suspicious ICMP packet (+ multi-host `09f9a9a7`, smurf `72694178`) | `f3389ebd` | oversized / multi-host / broadcast ICMP |
| 6 | Rare file transfer over SMB protocol | `045e06dd` | large copy to a rarely-used SMB share |

See `docs/verification-checklist.md`.

---

## 5. Safety
Native protocol clients only — FTP logins that fail, SSH banner exchanges, and
benign ICMP echoes. No data actually leaves beyond the lab targets you set.
`DryRun` sends nothing. Authorized labs only.
