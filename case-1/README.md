# EAL Demo — Case 1: AD Intrusion → Exfiltration

A self-contained demo that walks an attacker from **initial access** to **data
exfiltration** across five MITRE ATT&CK-aligned stages, and generates the
corresponding **Cortex XSIAM / XDR analytics alerts** — all driven by
**Palo Alto Networks Firewall EAL (Enhanced Application) logs**.

Every stage produces network traffic that a Palo Alto NGFW forwards to Cortex
as EAL logs; the Cortex analytics engine then raises the alerts listed below.
The scripts are native PowerShell, safe (no real exploitation, dummy payloads
only), and built to run on Windows.

> Alert reference source:
> <https://cortex-docs.paloaltonetworks.com/analytics-alerts/alerts-by-data-source/palo-alto-networks-firewall-eal-logs>

---

## 1. Attack-flow design & sketch

The scenario: an implant lands on a corporate workstation (`ATTACKER`), beacons
out for C2, maps Active Directory, steals credentials, moves laterally to a file
server, and finally exfiltrates data to an external storage service. The Palo
Alto firewall sits between the internal hosts and both the internet and the
internal server segment, so it observes **every** hop as EAL logs.

```
                         ┌──────────────────────────────────────────┐
                         │            Internet / External            │
                         │   demo-c2-lab.net      rare-storage-demo   │
                         └───────▲──────────────────────────▲────────┘
                                 │ (1) DGA + DNS tunnel      │ (5) big upload
                                 │                           │
   ┌─────────────────────────────┼───────────────────────────┼───────────────┐
   │                    PALO ALTO NGFW  (EAL logs → Cortex XSIAM/XDR)          │
   └───────┬─────────────────────┴───────────┬───────────────┴───────────────┘
           │ (2) LDAP recon                   │ (4) RPC: SchedTask + SVCCTL
           │ (3) Kerberoast RC4 / NTLM        │
   ┌───────▼──────────┐              ┌────────▼──────────┐        ┌───────────┐
   │   ATTACKER host  │              │   DC01 (corp)     │        │   FS01    │
   │ (compromised WS) │──────────────▶  Domain Controller│        │ FileServer│
   └──────────────────┘   (2)(3)     └───────────────────┘  (4)   └───────────┘
                                                                        ▲
                                                                        └── (4)

   Kill chain:  (1) C2 ─▶ (2) Discovery ─▶ (3) Cred Access ─▶ (4) Lateral ─▶ (5) Exfil
```

### Stage → tactic → alert map

| # | Stage (ATT&CK tactic) | What the script does | Alert(s) raised | Technique | Data source |
|---|----------------------|----------------------|-----------------|-----------|-------------|
| 1 | **Initial Access / C2** (TA0011 Command & Control, TA0010 Exfiltration) | Resolves ~60 random-looking domains, then smuggles >10 KB into DNS subdomains in a 10-min window | **Random-Looking Domain Names** (Medium) · **DNS Tunneling** (Low) | T1568.002 · T1071 / T1048 | **PAN Firewall EAL logs** |
| 2 | **Discovery** (TA0007) | Fires a rare combination of AD/LDAP enumeration queries at the DC | **Rare LDAP enumeration** (Low) | T1087 | **PAN Firewall EAL logs** |
| 3 | **Credential Access** (TA0006) | Requests RC4 service tickets (Kerberoast) + forces an NTLM auth by IP | **Weakly-Encrypted Kerberos TGT Response** (Info) · **Rare NTLM Usage by User** (Info) | T1556.001 · T1550 | **PAN Firewall EAL logs** |
| 4 | **Lateral Movement** (TA0008) | Creates/runs a remote scheduled task and remote service via MSRPC on a second host | **Rare Scheduled Task RPC activity** (Info) · **Rare Remote Service (SVCCTL) RPC activity** (Info) | T1021 / T1053 | **PAN Firewall EAL logs** |
| 5 | **Exfiltration** (TA0010) | Uploads a ~40 MB dummy blob to a rarely-seen storage/mail domain | **Massive upload to a rare storage or mail domain** (Info) | T1567.002 | **PAN Firewall EAL logs** |

> **Requirement check:** the demo uses **7 distinct EAL-log analytics alerts**
> across **5 kill-chain stages** with a proper *initial access* start — and
> **every** stage is sourced from Palo Alto Networks Firewall EAL logs, so the
> "at least one must be FW logs" requirement is satisfied several times over.
> (Alerts 1, 3, 4, 5 are *also* obtainable from the XDR agent; alert 2 is
> FW-EAL-only. This demo drives all of them purely from the firewall.)

---

## 2. Project layout

```
case-1/
├── README.md                          <- this document
├── Start-Demo.cmd                     <- DOUBLE-CLICK: self-elevating launcher
├── Start-Demo.ps1                     <- guided menu (configure / preflight / run)
├── config/
│   ├── lab-config.ps1                 <- defaults: domain, DC, targets, sizes
│   └── lab-config.local.ps1           <- your saved settings (auto-created by menu)
├── scripts/
│   ├── 00-preflight.ps1               <- connectivity / readiness checks
│   ├── 01-c2-dga-dns.ps1              <- Stage 1  (DGA + DNS tunnel)
│   ├── 02-discovery-ldap.ps1          <- Stage 2  (LDAP enumeration)
│   ├── 03-credaccess-kerberos-ntlm.ps1<- Stage 3  (Kerberoast RC4 + NTLM)
│   ├── 04-lateral-rpc.ps1             <- Stage 4  (SchedTask + SVCCTL RPC)
│   ├── 05-exfil-upload.ps1            <- Stage 5  (massive upload)
│   └── Run-All.ps1                    <- orchestrator (runs all stages)
└── docs/
    └── verification-checklist.md      <- alert-by-alert validation table
```

---

## 3. Lab / prerequisites (Windows)

| Component | Requirement |
|-----------|-------------|
| **Attacker host** | Windows 10/11 or Server 2019+, PowerShell 5.1+, domain-joined (recommended) |
| **Domain Controller** | Windows Server AD DS (`DC01`) reachable on 389/88 — target for stages 2–3 |
| **Lateral target** | A second Windows host (`FS01`) where the attacker account is local admin — target for stage 4 |
| **Palo Alto NGFW** | In-path between the hosts and the internet/server segment, with **Enhanced Application Logging enabled** and log forwarding to **Cortex XSIAM/XDR** |
| **Cortex** | XSIAM or XDR tenant ingesting the firewall EAL logs, **Analytics/ITDR enabled** |
| **Privileges** | Run the attacker scripts from an **elevated** PowerShell for stage 4 |

> **Minimal footprint:** Stages **1** and **5** only need outbound DNS/HTTPS
> through the firewall, so you can demo the C2 and exfil alerts on a single
> standalone Windows box with no AD lab. Stages 2–4 need the DC / lateral target.

### One-time firewall/Cortex setup (summary)
1. On the NGFW, enable **Enhanced Application Logging** (Device ▸ Setup ▸ Content-ID / in the Log Forwarding profile) so app/DNS/RPC metadata is captured.
2. Attach a **Log Forwarding profile** to the security rules covering the lab segments and forward to **Cortex Data Lake / XSIAM**.
3. In Cortex, confirm the **PAN Firewall EAL** data source is *green* and that **Analytics** (and **ITDR** for the Kerberos/NTLM detectors) is enabled.

---

## 4. Configure

**You normally don't configure anything by hand.** Launch `Start-Demo.cmd` and,
on first run, it offers to **auto-detect** from the machine it's running on. On a
domain-joined host it fills in:

| Setting | Auto-detected from |
|---------|--------------------|
| `LabUser` | current logged-on user (`$USERDOMAIN\$USERNAME`) |
| `Domain` | machine's AD domain (`$USERDNSDOMAIN` / current-domain lookup) |
| `DomainController` + `DCIpAddress` | nearest DC via `FindDomainController()`, IP resolved |
| `LateralTarget` + `LateralTargetIp` | first non-DC member server that answers on RPC/135 |

The results are saved to `config\lab-config.local.ps1` (which `lab-config.ps1`
loads last, overriding defaults). Re-run auto-detect any time via menu **[A]**.

**What auto-detect can't know** (external to your network) — set these via menu
**[1]** only if you control them; otherwise the defaults still generate
firewall-loggable traffic:

```powershell
DgaRootDomain = "demo-c2-lab.net"    # C2 / DGA parent domain you own
ExfilUrl      = "https://rare-storage-demo.example-upload.net/upload"
```

> Two things auto-detect proposes but you should **confirm**: that you actually
> have **admin rights** on the chosen `LateralTarget` (needed for stage 4), and
> that the picked server is an acceptable demo target. Change it with **[1]** if
> not. Everything else (payload sizes, pacing, `DryRun`) has a working default in
> `config\lab-config.ps1`.

---

## 5. Step-by-step execution guide

### Easiest path — one click

**Double-click `Start-Demo.cmd`** (or right-click ▸ *Run as administrator*). It
self-elevates, sets the execution policy for the run, and opens a guided menu:

```
  [1] Configure lab settings (no file editing)
  [2] Preflight - check connectivity
  [3] Dry run  - print the whole chain, send NO traffic
  [4] RUN full attack chain (pause between stages)
  [5] Run C2 + Exfil only  (stages 1 & 5, no AD lab needed)
  [6] Run a single stage...
  [7] Show expected Cortex alerts
```

Pick **[1]** once to set your domain/DC/target (saved to
`config\lab-config.local.ps1` — you never open a file), then **[2] → [3] → [4]**.
That's the whole demo. The manual commands below still work if you prefer them.

### Manual path

Open an **elevated Windows PowerShell** on the attacker host, `cd` to the
project, and allow the scripts to run for this session:

```powershell
cd D:\PANW\eal-demo\case-1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
```

### Step 0 — Preflight
```powershell
.\scripts\00-preflight.ps1
```
Confirms DNS egress, DC reachability, LDAP/389 and RPC/135. Fix any red items
before continuing (DNS-only stages still work if the AD checks fail).

### Step 1 — Rehearse safely (optional but recommended)
```powershell
.\scripts\Run-All.ps1 -DryRun
```
Prints every action *without sending traffic* so you can narrate the demo.

### Step 2 — Run the full chain
```powershell
.\scripts\Run-All.ps1 -PauseBetween
```
`-PauseBetween` waits for a keypress between stages so you can switch to the
Cortex console and show each detection landing. To run everything unattended,
drop the flag. To run a subset:

```powershell
.\scripts\Run-All.ps1 -Stages 1,5        # only C2 + exfil (no AD lab needed)
```

Or run stages individually:

```powershell
.\scripts\01-c2-dga-dns.ps1
.\scripts\02-discovery-ldap.ps1
.\scripts\03-credaccess-kerberos-ntlm.ps1
.\scripts\04-lateral-rpc.ps1
.\scripts\05-exfil-upload.ps1
```

### Step 3 — Watch Cortex
The EAL analytics detectors are **behavioural** and run on a schedule, so alerts
typically surface **~10–60 minutes** after the traffic (some, like DNS
tunnelling, evaluate over a 10-minute window). Keep the tenant open on the
Alerts/Incidents view.

---

## 6. What to expect in Cortex XSIAM / XDR

After the chain runs, verify each alert. In Cortex go to **Incidents & Alerts ▸
Alerts** and filter (e.g. by the attacker host, or `Alert Source = Analytics`).

| Stage | Expected alert name (search string) | Severity | ATT&CK | Pivot field to confirm |
|-------|-------------------------------------|----------|--------|------------------------|
| 1 | `Random-Looking Domain Names` | Medium | T1568.002 | Source host = ATTACKER; many NXDOMAIN root domains |
| 1 | `DNS Tunneling` | Low | T1071 / T1048 | Parent domain = `tunnel.demo-c2-lab.net`; >10 KB in 10 min |
| 2 | `Rare LDAP enumeration` | Low | T1087 | Source = ATTACKER → DC01 over LDAP/389 |
| 3 | `Weakly-Encrypted Kerberos TGT Response` | Informational | T1556.001 | RC4 / etype 23 ticket to DC01 |
| 3 | `Rare NTLM Usage by User` | Informational | T1550 | User `analyst` first NTLM in 30 days → FS01 by IP |
| 4 | `Rare Scheduled Task RPC activity` | Informational | T1021 / T1053 | ATTACKER → FS01, ITaskScheduler RPC |
| 4 | `Rare Remote Service (SVCCTL) RPC activity` | Informational | T1021 | ATTACKER → FS01, SVCCTL RPC |
| 5 | `Massive upload to a rare storage or mail domain` | Informational | T1567.002 | Large outbound flow → rare storage domain |

Because the stages share the same source host and timeframe, Cortex's stitching
should group several of these into a **single incident**, giving a clean
end-to-end intrusion story to walk a customer through. Use the
**Causality/Timeline** view to show the progression across the kill chain.

See `docs\verification-checklist.md` for a printable tick-box version.

---

## 7. Safety, scope & cleanup

- **No exploitation.** Scripts only generate *traffic patterns* — DNS queries,
  LDAP reads, Kerberos TGS requests, benign remote task/service create-then-
  delete, and an upload of locally-generated random bytes. Nothing sensitive
  leaves the host and no malware is deployed.
- **Self-cleaning.** Stage 4 deletes the remote task and service it creates;
  stage 5 deletes its temp payload file.
- **Authorized use only.** Run exclusively in a lab you own / are authorized to
  test. This is a detection-engineering / SE demo, not an offensive tool.
- **Tuning.** If an alert does not fire, it is usually because the behaviour was
  not yet "rare" enough (analytics baselines) or the log source/Analytics module
  is not fully enabled — see the checklist for troubleshooting notes.
