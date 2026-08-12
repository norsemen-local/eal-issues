# PANW EAL Demo — Real Attack Lifecycles for Cortex XSIAM/XDR

Five self-contained demo cases, each a **complete, role-correct attack
lifecycle** (initial access → … → objective), that generate **Palo Alto Networks
Firewall EAL-log** analytics and Threat-Prevention alerts in **Cortex XSIAM /
XDR**. A single orchestrator provisions the attacker, discovers all parameters,
and runs every case one at a time — unattended.

Alert reference:
<https://cortex-docs.paloaltonetworks.com/analytics-alerts/alerts-by-data-source/palo-alto-networks-firewall-eal-logs>

---

## Topology (roles)

```
   ┌─────────────────────┐         PAN NGFW (EAL + log forwarding)      ┌───────────────────┐
   │  KALI = ATTACKER/C2  │◀───────────────┬────────────────────────────▶│  WINDOWS = VICTIM  │
   │  170.187.158.212     │  victim⇄attacker traffic (all cases)         │  (runs the scripts) │
   │  phishing/C2/exfil    │                                              └─────────┬─────────┘
   └─────────────────────┘                                                         │ internal
                                                                          ┌────────▼────────┐
                                                                          │  DC / servers   │  (cases 3–4)
                                                                          └─────────────────┘
```

- **Kali** = the attacker: hosts the phishing page + payload, receives C2 beacons
  and exfil, and (case 2) actively exploits the victim.
- **Windows** = the victim endpoint where the scripts run; its malicious activity
  is outbound to the attacker / internal targets — how a compromised host behaves.
- **DC / member servers** = internal targets for the AD stages (cases 3–4).

---

## The five lifecycles

| Case | Lifecycle (Initial Access → … → Objective) | Direction | Doc |
|------|--------------------------------------------|-----------|-----|
| **1** | Phishing/drive-by → DGA C2 → DNS tunneling → exfil to rare domain | victim → attacker | [case-1](case-1/README.md) |
| **2** | Attacker exploits the victim's web app (traversal → Spring4Shell → web-shell) | attacker → victim | [case-2](case-2/README.md) |
| **3** | Phishing → RPC recon → DCOM / WinRM / SVCCTL / Scheduled-Task lateral movement | victim → internal | [case-3](case-3/README.md) |
| **4** | Phishing → LDAP recon → WPAD → EFSRPC → DCSync → Bronze Bit | victim → DC | [case-4](case-4/README.md) |
| **5** | Phishing → FTP → SSH → ICMP → SMB exfil to the attacker | victim → attacker | [case-5](case-5/README.md) |

Every stage maps to an EAL analytics rule that is enabled in the tenant; the
rule IDs are in each case's README §1 and printed at runtime.

---

## Quick start

### 1) Provision the attacker (Kali) — once
```powershell
# from the Windows victim (approve the 1Password/SSH prompt when it appears):
.\Invoke-AttackLifecycle.ps1 -Provision -DryRun     # show the plan
.\Invoke-AttackLifecycle.ps1 -Provision -Live       # provision + run all
```
Or run it on Kali by hand: `bash attacker/attacker-setup.sh` (see
[README-scenarios.md](README-scenarios.md)).

### 2) Run the lifecycles — from the Windows victim, elevated
```powershell
cd D:\PANW\eal-demo
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Invoke-AttackLifecycle.ps1 -DryRun                # rehearse everything, no traffic
.\Invoke-AttackLifecycle.ps1 -Live                  # run all 5, for real
.\Invoke-AttackLifecycle.ps1 -Cases 1,4,5 -Live     # a subset
```
It auto-detects the victim IP and the AD domain/DC, writes each case's config,
and runs the cases sequentially. Pass `-DomainController DC01.corp.local` etc. to
override. **Default is dry-run-safe** — `-Live` actually sends traffic.

A single case can also be run on its own: `case-N\Start-Demo.cmd` → menu.

---

## Repository layout

```
eal-demo/
├── README.md                     <- this file
├── README-lifecycle.md           <- the lifecycle model + orchestrator (start here)
├── README-scenarios.md           <- simpler "point everything at one server" runner
├── README-cases.md               <- the five cases + full stage→rule matrix
├── Invoke-AttackLifecycle.ps1    <- GLOBAL orchestrator (attacker + victim, unattended)
├── Run-Scenarios.ps1             <- simpler all-cases runner (victim-only)
├── attacker/                     <- runs on KALI
│   ├── attacker-setup.sh         <- phishing/C2/exfil + FTP/SSH/SMB + offensive tools
│   └── attack-web.sh             <- inbound web exploitation (case 2)
├── target-server/
│   └── setup-target-server.sh    <- lighter listener-only setup for the target box
├── _shared/                      <- shared launcher / Run-All / IA helpers (source copies)
└── case-1 … case-5/
    ├── README.md                 <- per-case design, flow, step-by-step, expected alerts
    ├── Start-Demo.cmd / .ps1     <- one-click per-case launcher
    ├── config/lab-config.ps1     <- params, DryRun, stage map
    ├── scripts/                  <- 00-preflight + stage scripts + Run-All
    └── docs/verification-checklist.md
```

---

## Prerequisites

| Component | Requirement |
|-----------|-------------|
| **Attacker** | The Kali box (`170.187.158.212`), provisioned with `attacker/attacker-setup.sh`. Cloud security group must allow inbound 21, 80, 445, 2201–2203. |
| **Victim** | A Windows host, PowerShell 5.1+, **elevated** (case 2 listener + cases 3/4 RPC). This is where the scripts run. |
| **Internal** | For cases 3–4, a real **DC / member servers** the victim can reach. |
| **NGFW** | The victim's egress to the attacker (and the DC) **must traverse a Palo Alto NGFW** with **Enhanced Application Logging (EAL) enabled** and **log forwarding to Cortex XSIAM/XDR**. |
| **Cortex** | XSIAM/XDR ingesting the firewall logs; Analytics (and ITDR for cases 3–4) enabled. |

> **The one hard requirement:** if the victim's traffic bypasses the firewall,
> nothing is logged. Verify egress routing before a live run.

---

## Safety & scope

These are **detection-engineering / SE demos** — benign by design: phishing uses
Palo Alto's own URL-Filtering test pages, payloads are dummy marker files, DNS
lookups and failed logins generate traffic patterns only. No malware, no real
exploitation. A few exact exploits (EFSRPC, DCSync, Bronze Bit) note the helper
tool needed and otherwise just generate the network traffic. Run **only** against
a lab you own or are authorized to test. `-DryRun` sends nothing.
