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

## 5. Real vs simulated — will the FW / XDR agent actually recognise this?

**Legend** — ✅ **REAL·instant (FW)**: signature/category, fires first-run. 🟡
**REAL·baseline (EAL)**: genuine traffic the analytic models, fires only after the
baseline matures. 🟠 **SIMULATED**: approximation — the exact detector needs a lab
property or a raw-socket tool the script can't produce.

| # | Stage | What the code ACTUALLY sends | Detection | Class | Source |
|---|-------|------------------------------|-----------|-------|--------|
| 1 | Phishing / drive-by IA | Real GETs to PANW URL-Filtering test pages + attacker-IP fetch | Phishing/malware URL categorisation | ✅ **REAL·instant** | FW (URL Filtering) |
| 2 | FTP anon + brute | Real `FtpWebRequest` logins: anonymous, ftp/ftp, then 8 brute users | FTP Anon/Default `68d806a3` + Multiple FTP Login Attempts `91db0f65` | 🟡 **REAL·baseline** (these two are enabled) | FW (EAL) |
| 3 | SSH uncommon / same host key | **Real SSH key exchange via the built-in `ssh.exe`** to each server:port — KEX presents the server host key on the wire, then disconnects before auth (no creds used). Falls back to banner-read if `ssh.exe` is absent | Multiple uncommon SSH servers, same host key `f154d651` | 🟡 **REAL·baseline** — needs the lab SSH servers to actually **share one host key** | FW (EAL) |
| 4 | SSH downgrade | Raw TCP connect that genuinely **writes** a legacy `SSH-1.5-…` / `SSH-1.99-…` client version string (the exact banner the analytic keys on) — but no cipher/KEX negotiation | Suspicious SSH Downgrade `f154f3c5` | 🟡 **REAL·baseline** (legacy banner is real) | FW (EAL) |
| 5 | ICMP covert channel | `Ping` sends oversized/random-payload echoes (1024–1472 B — real, not plain pings), a "sweep", and a `.255` broadcast (OS usually drops) | Suspicious ICMP `f3389ebd` (+ multi-host `09f9a9a7`, smurf `72694178`) | 🟡 real oversized-ICMP / 🟠 **SIMULATED** for the exact router-advert (needs a raw-socket tool) + multi-host (needs **distinct IPs**) | FW (EAL) |
| 6 | SMB exfil | Writes a real 20 MB random file, `Copy-Item` to `\\host\share` — genuine SMB session + large write over 445 | Rare file transfer over SMB `045e06dd` | 🟡 **REAL·baseline** | FW (EAL) |

**Bottom line:** stages 1 and 2 are the reliable signals (phishing instant; FTP
anon/brute rules are enabled). Stages 3, 4 and 6 now send **genuine** SSH
key-exchange / legacy-SSH-banner / large-SMB traffic that alerts once baselined —
stage 3 completes a real handshake so the host key is actually on the wire, but the
"same key" match still requires the **lab SSH servers to share one host key** (the
setup script socats 3 ports → one :22 key). **Stage 5 remains partly simulated** —
the oversized ICMP echoes are real, but the exact router-advertisement variant needs
a raw-socket crafting tool and the multi-host variant needs several distinct target
IPs (`lab-config.local.ps1` collapses everything to one IP). This case is entirely
firewall-sourced (no XDR-agent BIOC content).

---

## 6. Safety
Phishing uses benign test pages; native protocol clients only (failed FTP logins,
SSH banner exchanges, benign ICMP, an SMB copy). No data leaves beyond the lab
attacker you set. `DryRun` sends nothing. Authorized labs only.
