# Case 5 — Phishing Foothold → Data Theft over Covert Channels

**Lifecycle:** a Windows **victim** is phished, then exfiltrates data to the
**attacker** (Kali) over non-web protocols — FTP (anonymous + brute), SSH
(uncommon servers / downgrade), ICMP tunneling, and a rare SMB transfer. The Palo
Alto NGFW logs the FTP/SSH/ICMP/SMB traffic as **EAL logs**; Cortex XSIAM/XDR
raises the alerts. Several are FTP/SSH-EAL-only (no XDR-agent equivalent), so they
show cleanly as firewall-sourced.

- **Roles:** Kali = attacker / exfil receiver (`AttackerC2` / `FtpServer` /
  `SshServers` / `IcmpTarget` / `SmbShare`); this Windows host = victim.
  All traffic is victim → attacker.
- One of five cases — see [`../README.md`](../README.md).

---

## 1. Attack flow → enabled EAL rules

```
   (1) PHISHING ─▶ (2) FTP exfil ─▶ (3) SSH uncommon ─▶ (4) SSH downgrade ─▶ (5) ICMP ─▶ (6) SMB exfil
   VICTIM(Windows) ──FTP/SSH/ICMP/SMB──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR (ATTACKER=Kali)
```

| # | Stage (ATT&CK tactic) | What the victim does | Enabled EAL alert | Rule id | Technique |
|---|----------------------|----------------------|-------------------|---------|-----------|
| 1 | **INITIAL ACCESS** (TA0001) | Phishing / drive-by (victim → attacker) | **Phishing site access** + malware URL (URL Filtering) | *(URL Filtering)* | T1566 · T1204 |
| 2 | **Exfil staging** (TA0006/TA0010) | Anonymous + brute FTP to the attacker | **FTP Anonymous/Default Credentials** + **Multiple Suspicious FTP Login Attempts** | `68d806a3`, `91db0f65` | T1110 · T1078 |
| 3 | **Credential Access** (TA0006) | Connects to several uncommon SSH servers (same host key) | **Multiple uncommon SSH Servers with the same Server host key** | `f154d651` | T1557 |
| 4 | **Defense Evasion / LM** (TA0005/TA0008) | Announces legacy SSH-1.5/1.99 client banner | **Suspicious SSH Downgrade** | `f154f3c5` | T1021 · T1562.010 |
| 5 | **Command & Control** (TA0011) | Oversized + multi-host + broadcast ICMP | **Suspicious ICMP packet** (+ echo-to-multiple `09f9a9a7`, smurf `72694178`) | `f3389ebd` | T1572 |
| 6 | **Exfiltration** (TA0010) | Large file copy to a rarely-used SMB share | **Rare file transfer over SMB protocol** | `045e06dd` | T1570 |

---

## 2. Prerequisites
- Windows victim, PowerShell 5.1+.
- The Kali attacker box up (`attacker/attacker-setup.sh`): anon FTP :21, SSH on
  :2201–2203 (same host key), SMB guest share, ICMP. Traffic must traverse the
  PAN NGFW (EAL + log forwarding).
- The SSH "same host key" alert relies on the 3 ports sharing one key (the setup
  script does this via socat → :22).

---

## 3. Run it

```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 5 -Live       # attacker/exfil auto-points at Kali
```
Or standalone: **`case-5\Start-Demo.cmd`** → **[1] Configure** (attacker/C2, FTP,
SSH, ICMP, SMB) → **[2] → [3] → [4]**. Rejected FTP logins / SSH resets are
expected — the connection attempt is the firewall-observable signal.

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 | Phishing site access + malware URL | *(URL Filtering)* | victim → phishing/malware URL |
| 2 | FTP Anonymous/Default Credentials + Multiple Suspicious FTP Login Attempts | `68d806a3`, `91db0f65` | anon + many FTP logins to the attacker |
| 3 | Multiple uncommon SSH Servers with the same Server host key | `f154d651` | SSH to several ports sharing a key |
| 4 | Suspicious SSH Downgrade | `f154f3c5` | legacy SSH-1.5/1.99 client version |
| 5 | Suspicious ICMP packet (+ `09f9a9a7`, `72694178`) | `f3389ebd` | oversized / multi-host / broadcast ICMP |
| 6 | Rare file transfer over SMB protocol | `045e06dd` | large copy to a rarely-used SMB share |

See [`docs/verification-checklist.md`](docs/verification-checklist.md).

---

## 5. Safety
Phishing uses benign test pages; native protocol clients only (failed FTP logins,
SSH banner exchanges, benign ICMP, an SMB copy). No data leaves beyond the lab
attacker you set. `DryRun` sends nothing. Authorized labs only.
