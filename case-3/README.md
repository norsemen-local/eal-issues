# Case 3 — Phishing Foothold → Windows Lateral Movement

**Lifecycle:** a Windows **victim** is phished, then the compromised host pivots
across internal Windows systems using remote-admin RPC — an endpoint-mapper
sweep, sensitive RPC, DCOM activation, WinRM, and remote service / scheduled-task
execution. The Palo Alto NGFW logs the HTTP + MSRPC/WinRM traffic as **EAL logs**;
Cortex XSIAM/XDR raises the alerts.

- **Roles:** Kali = attacker / C2 (`AttackerC2`) for the phishing entry; this
  Windows host = victim (runs the scripts); the **DC / member servers** are the
  internal lateral-movement targets.
- Behavioural detectors — with an XDR agent on the victim some may be attributed
  to the endpoint; run from a non-agent host for clean firewall attribution.
- One of five cases — see [`../README.md`](../README.md).

---

## 1. Attack flow → enabled EAL rules

```
   (1) PHISHING ─▶ (2) RPC sweep ─▶ (3) sensitive RPC ─▶ (4) DCOM ─▶ (5) WinRM ─▶ (6) SVCCTL+SchedTask
   VICTIM(Windows) ──HTTP + MSRPC/WinRM──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR
```

| # | Stage (ATT&CK tactic) | What the victim does | Enabled EAL alert | Rule id | Technique |
|---|----------------------|----------------------|-------------------|---------|-----------|
| 1 | **INITIAL ACCESS** (TA0001) | Phishing / drive-by (victim → attacker) | **Phishing site access** + malware URL (URL Filtering) | *(URL Filtering)* | T1566 · T1204 |
| 2 | **Discovery** (TA0043) | Probes RPC endpoint mapper (135) across many hosts | **Abnormal RPC traffic to multiple hosts** | `77034682` | T1595 |
| 3 | **Lateral Movement** (TA0008) | WMI/DCOM + SCM queries across many hosts | **Abnormal sensitive RPC traffic to multiple hosts** | `1820b60e` | T1021 |
| 4 | **Lateral Movement** (TA0008) | Activates DCOM objects on a remote host | **Rare DCOM RPC activity** | `9c37ef68` | T1021.003 |
| 5 | **Lateral Movement** (TA0008) | `Invoke-Command` / `Test-WSMan` over WinRM (5985) | **Rare Windows Remote Management (WinRM) HTTP Activity** | `927b7285` | T1021 |
| 6 | **Lateral Movement** (TA0008) | Remote service (SVCCTL) + scheduled-task RPC | **Rare Remote Service (SVCCTL) RPC** + **Rare Scheduled Task RPC** | `a7825b28`, `fc8b21f4` | T1021 · T1053 |

---

## 2. Prerequisites
- Windows victim, PowerShell 5.1+, **elevated** (DCOM/WMI/SCM). Prefer a
  non-agent host for clean firewall attribution.
- Several reachable Windows hosts (`SweepHosts`); a member server for
  DCOM/WinRM/SchedTask (`LateralTarget`); lab account admin on targets.
- Traffic must traverse the PAN NGFW (EAL + log forwarding). "To multiple hosts"
  detectors want **several distinct** target IPs.

---

## 3. Run it

```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 3 -DomainController DC01.corp.local -LateralTarget FS01.corp.local -SweepHosts "10.0.0.10,10.0.0.20,10.0.0.21" -Live
```
Or standalone: **`case-3\Start-Demo.cmd`** → **[1] Configure** (attacker/C2, DC,
target, sweep hosts) → **[2] → [3] → [4]**. Failed remote calls (no admin, host
down) are expected and still generate the RPC/WinRM traffic.

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 | Phishing site access + malware URL | *(URL Filtering)* | victim → phishing/malware URL |
| 2 | Abnormal RPC traffic to multiple hosts | `77034682` | victim → many hosts on 135 |
| 3 | Abnormal sensitive RPC traffic to multiple hosts | `1820b60e` | WMI/SCM RPC to many hosts |
| 4 | Rare DCOM RPC activity | `9c37ef68` | DCOM activation to the target |
| 5 | Rare WinRM HTTP Activity | `927b7285` | WinRM 5985 to the target |
| 6 | Rare SVCCTL RPC + Rare Scheduled Task RPC | `a7825b28`, `fc8b21f4` | remote service + task on the target |

Cortex should stitch these into one lateral-movement incident. See
[`docs/verification-checklist.md`](docs/verification-checklist.md).

---

## 5. Real vs simulated — will the FW / XDR agent actually recognise this?

**Legend** — ✅ **REAL·instant (FW)**: signature/category, fires first-run. 🟡
**REAL·baseline (EAL)**: genuine traffic the analytic models, fires only after the
baseline matures. 🟠 **SIMULATED**: approximation only.

Every lateral-movement stage makes a **real remote-admin call** via a native tool
(`sc.exe`, `schtasks`, `Get-WmiObject`, DCOM `Activator.CreateInstance`,
`Invoke-Command`) — genuine MSRPC/DCOM/WinRM/SVCCTL exchanges, **not** bare TCP
connects. So nothing here is cosmetic; the catch is that these are all
**rarity/volume behavioural analytics** that need a matured baseline, and on an
agent host they get **attributed to the XDR endpoint agent instead of the firewall.**

| # | Stage | What the code ACTUALLY sends | Detection | Class | Source |
|---|-------|------------------------------|-----------|-------|--------|
| 1 | Phishing / drive-by IA | Real GETs to PANW URL-Filtering test pages + attacker-IP fetch | Phishing/malware URL categorisation | ✅ **REAL·instant** | FW (URL Filtering) |
| 2 | RPC / 135 sweep | `Test-NetConnection -Port 135` + real `sc.exe \\host query type= driver` (SVCCTL RPC) ×5 hosts | Abnormal RPC to multiple hosts `77034682` | 🟡 **REAL·baseline** | FW — **agent-shadowed** |
| 3 | Sensitive RPC | Real `Get-WmiObject Win32_Service -ComputerName` (WMI/DCOM) + `sc.exe` ×5 hosts | Abnormal sensitive RPC to multiple hosts `1820b60e` | 🟡 **REAL·baseline** | FW — **agent-shadowed** |
| 4 | DCOM activation | Real remote `Activator::CreateInstance` of MMC20 / Shell / Excel objects over RPC | Rare DCOM RPC `9c37ef68` | 🟡 **REAL·baseline** | FW — **agent-shadowed** |
| 5 | WinRM | Real `Test-WSMan` + `Invoke-Command` over WinRM 5985 | Rare WinRM HTTP `927b7285` | 🟡 **REAL·baseline** | FW — **agent-shadowed** |
| 6 | SVCCTL + Scheduled Task | Real `sc.exe \\target create/delete` + `schtasks /s target` (ATSVC RPC), self-cleaning | Rare SVCCTL RPC `a7825b28` + Rare Scheduled Task RPC `fc8b21f4` | 🟡 **REAL·baseline** | FW — **agent-shadowed** |

**Bottom line:** **no simulated-only stages** — the traffic is genuine RPC. But
only stage 1 fires first-run; stages 2–6 need a matured baseline **and** the
"rare / to multiple hosts" conditions, so re-run from a **fresh, non-agent source
host** with **several distinct target IPs** for clean firewall attribution. If an
XDR agent is on the victim, expect these as endpoint BIOCs (with a process name)
rather than firewall EAL alerts — this shadowing is intentional and documented.
Note: `lab-config.local.ps1` collapses the sweep/target/DC to a single host, which
weakens the "multiple hosts" condition — override `-SweepHosts` at runtime.

---

## 6. Safety
Phishing uses benign test pages; remote object/service/task calls create-and-
delete; failures swallowed. Authorized labs only. `DryRun` sends nothing.
