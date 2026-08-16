# PANW EAL Demo — Real Attack Lifecycles for Cortex XSIAM/XDR

**Ten** self-contained demo cases, each a **complete, role-correct attack
lifecycle** with a start → middle → end, that generate **Palo Alto Networks
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
   │                       │  victim⇄attacker traffic (all cases)         │  (runs the scripts) │
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

## The ten lifecycles

| Case | Story — Lifecycle (start → middle → end) | Direction | Doc |
|------|------------------------------------------|-----------|-----|
| **1** | *Drive-by to Data Theft* — phishing → DGA C2 → DNS tunneling → rare-domain exfil | victim → attacker | [case-1](case-1/README.md) |
| **2** | *Web-App Breach* — attacker exploits the victim's web app (traversal → Spring4Shell → web-shell) | attacker → victim | [case-2](case-2/README.md) |
| **3** | *Lateral Movement* — phishing → RPC recon → DCOM / WinRM / SVCCTL / Scheduled-Task | victim → internal | [case-3](case-3/README.md) |
| **4** | *AD Domination* — phishing → LDAP recon → WPAD → EFSRPC → DCSync → Bronze Bit | victim → DC | [case-4](case-4/README.md) |
| **5** | *Covert Exfil* — phishing → FTP → SSH → ICMP → SMB exfil | victim → attacker | [case-5](case-5/README.md) |
| **6** | *Ghost in the DNS* — phishing → subdomain fuzzing → dyn-DNS → rare TLS/UA → recurring rare-domain C2 | victim → attacker | [case-6](case-6/README.md) |
| **7** | *Poisoned Well* — phishing → rogue MS-Update server → update over HTTP → unmanaged device → trojan C2 | victim → attacker | [case-7](case-7/README.md) |
| **8** | *The Departing Employee* — job-hunting/browsing tells → new/rare FTP → massive upload (insider) | insider → drop | [case-8](case-8/README.md) |
| **9** | *Pass-the-Hash Playbook* — phishing → long-user/NTLM → machine NTLM → RC4 Kerberos → ADFS/Golden SAML | victim → DC/ADFS | [case-9](case-9/README.md) |
| **10** | *Tunnels & Shadows* — phishing → uncommon SSH → SSH tunnel → rare ad-domains → remote task persistence | victim → attacker | [case-10](case-10/README.md) |

Every stage maps to an EAL rule (IDs in each case's README §1, printed at runtime).

---

## What fires instantly vs what needs a baseline (read before a demo)

The single most important thing to understand before a live run — not all Cortex
detections behave the same:

| Detection class | Source | Timing | Examples |
|-----------------|--------|--------|----------|
| **URL Filtering** | **PAN NGFW** | **Instant** (pattern) | Phishing site access, malware URL |
| **DNS Security categories** | **PAN NGFW** | **Instant** (category match) | Dns-C2, DGA, DNS-tunnel, dynamic-DNS, fast-flux, ad-tracking, malware, fake-software, dns-infiltration, proxy, subdomain-reputation, strategically-aged, ransomware, NRD |
| **Vulnerability signatures** | **PAN NGFW** | **Instant** (pattern) | Spring4Shell, path traversal, LFI, web-shell params |
| **Behavioural EAL analytics** | FW EAL logs | **Baseline: 30-day train + 14-day activate** — will NOT fire on a first run | Random-Looking Domain Names, DNS Tunneling (analytic), Subdomain Fuzzing, recurring rare-domain, rare TLS+UA, uncommon/unusual SSH, MS-Update trio, rare DCOM/WinRM/RPC, rare LDAP enumeration |
| **Identity analytics (ITDR)** | FW EAL logs | **Baseline + ITDR + AD lab** | Rare NTLM, NTLM machine-account, weak Kerberos TGT, ADFS sync, DCSync, Bronze Bit |
| **Endpoint (agent) BIOCs** | **XDR agent** | Instant, but **shadows** the FW behavioural analytics on an agent host | "LOLBIN connected to rare host", uncommon SSH, remote scheduled task |

**Why every stage has a DNS-Security "anchor":** to make each stage produce a
**reliable, firewall-sourced PAN NGFW** detection on the *first* run, every stage
of cases 6–10 resolves a category-matched Palo Alto DNS-Security **test domain**
(`*.testpanw.com`) — instant, no baseline. The named behavioural/identity EAL
analytics are the **bonus layer** that matures over the training window (and can
be out-raced by the XDR agent on a monitored host), not the demo backbone. Each
case README has a **Detection model** section spelling this out.

> Demonstrating a *specific behavioural rule name* (e.g. "Subdomain Fuzzing") as a
> hard requirement needs its training window to elapse or a pre-seeded baseline —
> no script can force a baseline detector to fire immediately.

Cases 1–5 map to enabled rules; 6–7 & 10 lean on enabled rules + DNS-Security
anchors; 8–9 (insider + identity) add DNS-Security anchors so they still fire even
though their behavioural detectors may need enabling/baselining — noted per case.

---

## What each case does, what it shows in XSIAM, and what's real vs simulated

This is the section to read if you want to know, for any stage, **"will the
firewall / XDR agent actually recognise this, or is it only a simulation?"** Every
stage falls into one of four buckets:

| Class | Meaning | Does it really get recognised? |
|-------|---------|--------------------------------|
| ✅ **REAL · instant (FW)** | Hits a Palo Alto **URL-Filtering / DNS-Security test resource** or a real **Vulnerability/Threat signature** (e.g. `*.testpanw.com`, `urlfiltering.paloaltonetworks.com` test pages, the genuine Spring4Shell payload string). | **Yes — on the first run**, no baseline. The NGFW categorises/signature-matches and usually **blocks/sinkholes**. This is the demo backbone. |
| 🟡 **REAL · baseline (EAL / ITDR)** | Emits **genuine, correctly-shaped traffic** (real DGA-looking DNS, real DNS tunnelling, real FTP/SSH/RPC/DCOM/WinRM/NTLM/Kerberos sessions) that the named behavioural analytic is designed to model. | **Yes, it's real traffic — but not first-run.** The analytic only fires after its **~30-day train + 14-day activate** baseline matures (identity analytics also need **ITDR + a real AD/ADFS lab**). On a fresh tenant these look silent. |
| 🔵 **REAL · endpoint (XDR agent BIOC)** | A **real host action** the XDR agent observes: encoded PowerShell, `certutil`/`bitsadmin` LOLBIN fetch, HKCU Run-key, file-association hijack, rogue root-CA, cert-store access, data-staging zip. All auto-revert. | **Yes — if an XDR agent is installed on the victim**, mostly same-run. On an agent host these also **shadow** the firewall's behavioural analytic (the agent wins attribution). |
| 🟠 **SIMULATED (traffic-only)** | Only **approximates** the footprint — opens the surface or sends look-alike traffic but never performs the defining protocol call/exploit. | **No — the exact named detector will not truly fire** without a real offensive tool (mimikatz, Rubeus, Impacket, PetitPotam) or a specific lab property. The co-located test-domain anchor still fires ✅. |

**The one rule of thumb:** on a **fresh tenant / first run**, only the ✅ instant
layer (and 🔵 endpoint BIOCs, where an agent is present) actually alert. Everything
🟡 is real traffic that needs its baseline to mature or be seeded, and everything
🟠 is a visual stand-in whose exact detector needs a real tool. **Nothing in this
repo runs real malware or real memory-corruption exploits** — the web-attack
*strings* in case 2 are genuine (so signatures match), but the AD/identity exploits
in cases 4 & 9 are surface-traffic only.

### Per-case summary

| Case | What it does (lifecycle) | What you should see in XSIAM | ✅ Instant hits (first run) | 🟠 Simulated-only stages (won't truly fire without a tool/lab) |
|------|--------------------------|------------------------------|----------------------------|----------------------------------------------------------------|
| **1 — Drive-by to Data Theft** | Phished victim beacons out: 45-domain DGA flood, ~15 KB DNS tunnelling, malformed/failed DNS, recurring rare-domain exfil. | URL-Filtering phishing/malware + DNS-Security sinkholes instantly; the DGA / tunnel / rare-domain **EAL analytics** once baselined. | Phishing/malware URL-Filtering; `test-dga`, `test-dnstun`, `test-dns-infiltration`.testpanw.com sinkholes. | None. *(No stage runs the labelled "Spring4Shell" — IA is phishing; see case doc.)* |
| **2 — Web-App Exploitation** | Sends real malicious HTTP at a web app: path traversal, genuine Spring4Shell payload, web-shell/SSTI params, rare UA, covert PUT/PATCH exfil. | Vulnerability-Protection **blocks/resets** on the first request (stages 1-3); the rare-UA and HTTP-anomaly analytics once baselined. | Path traversal `60da6e16`, Spring4Shell `1028c23d`, suspicious params `3508f6b4` — real signatures, first-run. | **None** — every stage sends authentic attack content over the wire. |
| **3 — Lateral Movement** | Real remote-admin from the victim: EPM/135 sweep, WMI+SCM queries, DCOM activation, WinRM, remote service + scheduled task. | Rarity/volume **RPC/DCOM/WinRM/SVCCTL** analytics once baselined; on an agent host these are **attributed to the XDR agent** (shadowing). | Phishing/malware URL-Filtering (stage 1). | **None** — real RPC/DCOM/WinRM/SVCCTL/schtasks calls, not just TCP connects. |
| **4 — AD Domination** | Phish → real LDAP enum + WPAD → then **EFSRPC, DCSync, Bronze Bit** — but only the SMB/RPC/Kerberos *surface* is touched. | Instant phishing hit; LDAP/WPAD analytics once baselined + ITDR; the three exploit detectors **will not fire** as shipped. | Phishing/malware URL-Filtering (stage 1). | **EFSRPC/PetitPotam, DCSync, Bronze Bit** — need PetitPotam / mimikatz / Rubeus / Impacket. |
| **5 — Covert Exfil** | Phish → FTP anon+brute → uncommon SSH → SSH downgrade banner → oversized ICMP → 20 MB SMB copy. | Instant phishing + FTP anon/brute analytics; SSH-downgrade & rare-SMB once baselined. | Phishing/malware URL-Filtering (stage 1). | **SSH same-host-key** (banner-only, no key exchange; is a target-server property) and **ICMP router-advert / multi-host / smurf** (needs a raw socket + distinct IPs). |
| **6 — Ghost in the DNS** | Phish → 60-subdomain fuzzing → dyn-DNS rotation → rare TLS+UA beacon → slow recurring rare-domain C2, plus real endpoint implant actions. | Instant URL-Filtering + 6 DNS-Security categories; endpoint BIOCs (encoded PS, `certutil` LOLBIN, Run-key); the 4 named DNS EAL analytics need baseline. | Phishing + `subdomain-reputation`, `dga`, `ddns`, `fastflux`, `c2`, `strategically-aged`.testpanw.com. | None (the TLS stage uses a default JA3, not a crafted one, but still real traffic). |
| **7 — Poisoned Well** | Phish → rogue MS-Update (WSUS) server → trojanised update over HTTP → "unmanaged device" → trojan C2, plus rogue root-CA / LOLBIN endpoint actions. | Instant URL-Filtering + `fake-software`/`malware`/`c2` DNS-Security; endpoint BIOCs (root-CA, AppData drop, `bitsadmin`); MS-Update EAL analytics need baseline. | Phishing + `test-fake-software`, `test-malware`, `test-c2`.testpanw.com. | **Stage 4 "unique client computer model"** — HTTP headers can't populate the native WSUS inventory field the analytic reads. |
| **8 — Departing Employee** | *No phishing.* Insider browses job-boards/streaming → stages a real zip → new/rare **FTP** exfil → real **45 MB** upload. | FTP New-Server/rare-user analytics (enabled) + DNS-Security instant; job-hunting & massive-upload analytics may be **off/baselined**. | `test-dns-infiltration`, `test-proxy`.testpanw.com. FTP rules fire near-real-time (enabled). | None *(all traffic real; but the exact "massive upload to rare storage" detector may miss — the fabricated destination isn't a categorised online-storage domain).* |
| **9 — Pass-the-Hash Playbook** | Phish → long-user/rare NTLM → machine-account NTLM → RC4 Kerberos TGT → ADFS sync / Golden SAML. **Needs a real AD/ADFS lab + ITDR.** | Instant phishing + DNS-Security anchors; identity analytics only with **ITDR + real AD/ADFS + baseline**; one endpoint BIOC (cert-store access). | Phishing + `test-c2`, `test-malware`, `test-dns-infiltration`.testpanw.com. | **Golden SAML forgery** (never performed) and **RC4 downgrade** (etype not forced — exact RC4-TGT signal not guaranteed on AES-default AD). |
| **10 — Tunnels & Shadows** | Phish → uncommon SSH (raw-socket banner) → ~640 KB "tunnel" volume → rare ad-domains → remote scheduled-task persistence, plus a file-assoc hijack. | Instant URL-Filtering + `dnstun`/`adtracking` DNS-Security; SSH & remote-task EAL analytics need baseline; endpoint BIOC (file-assoc), agent shadows the remote-task on the target. | Phishing + `test-dnstun`, `test-adtracking`.testpanw.com. | **Stage 4 fake ad-domains** (invented `.net` names, not in PANW's advertising category — only the co-located `test-adtracking` anchor fires). |

Each case's own README has the full per-stage breakdown (`## Real vs simulated`),
including which detection is firewall-sourced vs XDR-agent-sourced.

---

## Quick start

### 0) Passwordless SSH to the attacker — once
So you never retype the Kali password: install an SSH key on the attacker (enter
the password **one** time; nothing is stored in plaintext). Every `ssh`/`scp` and
the orchestrator are passwordless afterwards.
```powershell
.\Setup-AttackerAuth.ps1                 # root@ by default
```

### 1) Provision the attacker (Kali) — once
```powershell
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
├── Setup-AttackerAuth.ps1        <- one-time: passwordless SSH key to the attacker
├── Invoke-AttackLifecycle.ps1    <- GLOBAL orchestrator (attacker + victim, unattended)
├── Run-Scenarios.ps1             <- simpler all-cases runner (victim-only)
├── attacker/                     <- runs on KALI
│   ├── attacker-setup.sh         <- phishing/C2/exfil + FTP/SSH/SMB + offensive tools
│   └── attack-web.sh             <- inbound web exploitation (case 2)
├── target-server/
│   └── setup-target-server.sh    <- lighter listener-only setup for the target box
├── _shared/                      <- shared launcher / Run-All / IA helpers (source copies)
└── case-1 … case-10/
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
| **Attacker** | The Kali box (``), provisioned with `attacker/attacker-setup.sh`. Cloud security group must allow inbound 21, 80, 445, 2201–2203. |
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
