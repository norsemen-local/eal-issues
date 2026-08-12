# Firewall Demo — Case 1: Detect **and Block** the Kill Chain

A self-contained demo that walks an attacker through five MITRE ATT&CK stages —
**initial access → C2 → DGA/DNS-tunneling → malware staging → exfiltration** —
and has the **Palo Alto Networks NGFW itself detect and BLOCK** each stage,
producing **firewall threat logs** (and analytics) in **Cortex XSIAM / XDR**.

Every alert this demo produces is **firewall-sourced** — DNS Security sinkholes,
URL Filtering blocks, Antivirus resets — which means it is **not shadowed by the
Cortex XDR agent**. It does not matter that every host in your lab is onboarded
to the agent; the firewall's own enforcement logs show up regardless.

All traffic uses Palo Alto Networks' **official, 100 % benign test resources**
(`*.testpanw.com` DNS Security test domains and the
`urlfiltering.paloaltonetworks.com` URL Filtering test pages). **No malware, no
exploitation, no real C2.**

> Why this design? See §8 — "Firewall-sourced vs agent-sourced." The earlier
> EAL behavioural-analytics approach got attributed to the XDR agent because the
> agent has richer endpoint telemetry. Firewall Threat-Prevention enforcement
> does not have that problem.

---

## 1. Attack-flow design & sketch

```
        ┌──────────────────────────────────────────────────────────────┐
        │   Palo Alto benign TEST destinations (safe, no real threat)   │
        │   urlfiltering.paloaltonetworks.com   *.testpanw.com          │
        └──────▲───────────▲───────────▲───────────▲───────────▲────────┘
   (1) phishing│  (2) C2   │ (3) DGA / │ (4) malware/│ (5) DNS-exfil│
      /malware │  URL+DNS  │ DNS-tunnel│ ransomware  │  + anonymizer│
       URL     │           │           │             │              │
   ┌───────────┴───────────┴───────────┴─────────────┴──────────────┴──┐
   │        PALO ALTO NGFW  — inspects every request, then:            │
   │  DNS Security ▸ sinkhole   URL Filtering ▸ block   AV/WildFire ▸ reset │
   │        → THREAT / URL logs forwarded to Cortex XSIAM / XDR         │
   └───────────────────────────────▲──────────────────────────────────┘
                                    │ all 5 stages
                          ┌─────────┴─────────┐
                          │   ATTACKER host    │  (any Windows box,
                          │  Run-All.ps1       │   agent installed is fine)
                          └────────────────────┘

   Kill chain:  (1) Initial Access ─▶ (2) C2 ─▶ (3) DGA/Tunnel ─▶ (4) Staging ─▶ (5) Exfil
   Firewall:    BLOCK ──────────────▶ BLOCK+SINKHOLE ─▶ SINKHOLE ─▶ SINKHOLE+BLOCK ─▶ SINKHOLE+BLOCK
```

### Stage → tactic → firewall action → alert

| # | Stage (ATT&CK tactic) | Traffic generated (benign test resource) | Firewall mechanism | Action | Firewall log in XSIAM |
|---|----------------------|------------------------------------------|--------------------|--------|-----------------------|
| 1 | **Initial Access** (TA0001) | GET `test-phishing`, `test-malware` URL pages *(+ optional EICAR)* | **URL Filtering** (+ Antivirus) | **block** / reset | URL Filtering log · Threat (virus) log |
| 2 | **Command & Control** (TA0011) | GET `test-command-and-control`; resolve `test-c2.testpanw.com` | URL Filtering + **DNS Security** | block + **sinkhole** | URL log · DNS Threat log (sinkhole) |
| 3 | **DGA / DNS Tunneling** (TA0011) | resolve `test-dga`, `test-dnstun`, `test-ddns`, `test-fastflux` `.testpanw.com` | **DNS Security** | **sinkhole** / alert | DNS Threat logs (DGA, tunnel, DDNS, fast-flux) |
| 4 | **Malware/Ransomware Staging** (TA0011/TA0040) | resolve `test-malware`, `test-ransomware`, `test-nrd`; GET `test-high-risk` | DNS Security + URL Filtering | sinkhole + block | DNS Threat + URL logs |
| 5 | **Exfiltration** (TA0010) | resolve `test-dns-infiltration`, `test-dnstun`, `test-proxy` `.testpanw.com` | DNS Security + URL Filtering | sinkhole + block | DNS Threat + URL logs |

> **Detect *and* block:** set some Threat-Prevention signatures/categories to
> **alert** (detect-only, traffic passes) and others to **block / sinkhole /
> reset**. Both write a firewall Threat log → a firewall-sourced alert in XSIAM.
> That is the whole "detect AND block" story, told entirely by the firewall.

### MITRE technique references

| Stage | Techniques |
|-------|-----------|
| 1 | T1566 Phishing · T1189 Drive-by Compromise · T1204 User Execution |
| 2 | T1071 Application Layer Protocol · T1571 Non-Standard Port |
| 3 | T1568.002 Dynamic Resolution: DGA · T1071.004 DNS |
| 4 | T1105 Ingress Tool Transfer · T1608 Stage Capabilities · T1486 Data Encrypted for Impact |
| 5 | T1041 Exfil over C2 · T1048 Exfil over Alternative Protocol · T1071.004 DNS |

---

## 2. Project layout

```
case-1/
├── README.md                          <- this document
├── Start-Demo.cmd                     <- DOUBLE-CLICK: self-elevating launcher
├── Start-Demo.ps1                     <- guided menu
├── config/
│   ├── lab-config.ps1                 <- test resources, pacing, DryRun
│   └── lab-config.local.ps1           <- optional per-machine overrides (auto-created)
├── scripts/
│   ├── 00-preflight.ps1               <- firewall/DNS/HTTP reachability checks
│   ├── _traffic.ps1                   <- shared URL/DNS traffic generators
│   ├── 01-initial-access-url.ps1      <- Stage 1  (URL Filtering + AV)
│   ├── 02-command-control.ps1         <- Stage 2  (URL + DNS sinkhole)
│   ├── 03-dga-dns-tunneling.ps1       <- Stage 3  (DNS Security)
│   ├── 04-malware-ransomware.ps1      <- Stage 4  (DNS + URL)
│   ├── 05-exfiltration-dns.ps1        <- Stage 5  (DNS + anonymizer)
│   ├── Run-All.ps1                    <- orchestrator
│   └── optional-ad-eal/               <- OPTIONAL behavioural add-on (see §9)
│       ├── 02-discovery-ldap.ps1
│       ├── 03-credaccess-kerberos-ntlm.ps1
│       └── 04-lateral-rpc.ps1
└── docs/
    └── verification-checklist.md      <- alert-by-alert validation table
```

---

## 3. Prerequisites (much simpler than an AD lab)

| Component | Requirement |
|-----------|-------------|
| **Attacker host** | **One** Windows 10/11 or Server box, PowerShell 5.1+. **Having the XDR agent installed is fine.** No admin rights or AD membership required. |
| **Path** | The host's **DNS and HTTP egress must traverse the Palo Alto NGFW** (not a direct/bypass path), so the firewall can inspect and block it. |
| **NGFW** | A security rule covering the host with **Anti-Spyware (DNS Security)**, **URL Filtering**, **Antivirus**, and ideally **WildFire** profiles attached, and **log forwarding to Cortex XSIAM/XDR** enabled. |
| **Cortex** | XSIAM or XDR tenant ingesting the firewall's Threat / URL logs. |
| **Licenses** | Active **DNS Security** and **Advanced URL Filtering** subscriptions on the firewall (required for the test domains/pages to be categorized and enforced). |

---

## 4. One-time firewall configuration (the important part)

To make the demo show **both detection and blocking**, configure the security
rule that applies to the attacker host:

1. **Anti-Spyware / DNS Security profile** — enable the DNS Security categories
   and set **Policy Action**:
   - `Command-and-Control`, `Malware`, `DGA`, `DNS Tunneling`, `Ransomware` →
     **sinkhole** (this is the "block" — clients get the PANW sinkhole IP).
   - `Dynamic DNS`, `Newly-Registered-Domains`, `Grayware`, `Proxy Avoidance` →
     **alert** (this is the "detect" — traffic passes but is logged).
   - Sinkhole IPv4 default: `sinkhole.paloaltonetworks.com` (72.5.65.111).
2. **URL Filtering profile** — set `command-and-control`, `malware`,
   `phishing` → **block**; `high-risk`, `medium-risk` → **alert**.
3. **Antivirus / WildFire profile** — default block actions (only relevant if
   you enable the optional EICAR test and have decryption on).
4. **Log Forwarding profile** — forward **Threat** and **URL** logs to
   **Cortex Data Lake / XSIAM**, and attach it to the security rule.
5. Confirm in Cortex that the **Palo Alto Networks NGFW** data source is healthy.

> Tip: keeping a *mix* of `sinkhole`/`block` and `alert` actions is what lets one
> run demonstrate the firewall both **catching** (alert) and **stopping** (block)
> the attack.

---

## 5. Step-by-step execution guide

### Easiest — one click
**Double-click `Start-Demo.cmd`** → menu:
```
  [2] Preflight  - check firewall/DNS/HTTP reachability
  [3] Dry run    - print the whole chain, send NO traffic
  [4] RUN full attack chain (pause between stages)
  [5] Run a single stage...
  [6] Show expected firewall alerts
```
Run **[2] → [3] → [4]**. No configuration needed — the demo has no lab values to
set (test resources are built in).

### Manual
```powershell
cd D:\PANW\eal-demo\case-1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\00-preflight.ps1
.\scripts\Run-All.ps1 -DryRun          # rehearse, sends nothing
.\scripts\Run-All.ps1 -PauseBetween    # full chain, pause per stage
.\scripts\Run-All.ps1 -Stages 2,3      # any subset
.\scripts\03-dga-dns-tunneling.ps1     # any stage standalone
```

The scripts print `[BLOCK]` (magenta) when the firewall blocks/sinkholes a
request and `[OK]` when it was only categorized/alerted — but **the firewall log
is generated either way**, so both are wins. A blocked HTTP request or an
NXDOMAIN/sinkhole DNS answer is *expected* and never fatal.

---

## 6. What to expect in Cortex XSIAM / XDR

Firewall Threat/URL logs appear in **near real-time** (minutes) — much faster
than behavioural analytics. In Cortex go to **Incidents & Alerts** (or **Query
Center**) and filter to the attacker host / firewall source.

| Stage | Firewall alert / log | Action | ATT&CK | Confirm |
|-------|----------------------|--------|--------|---------|
| 1 | URL Filtering: phishing, malware | block | T1566/T1189 | URL log, category=phishing/malware, action=block |
| 1 | Antivirus (if EICAR on) | reset-both | T1204 | Threat log, subtype=virus |
| 2 | URL Filtering: command-and-control | block | T1071 | URL log, category=command-and-control |
| 2 | DNS Security: `test-c2` | sinkhole | T1071 | Threat log, subtype=spyware/dns, action=sinkhole |
| 3 | DNS Security: DGA / DNS-tunnel / DDNS / fast-flux | sinkhole/alert | T1568.002/T1071.004 | Threat log(s), DNS categories |
| 4 | DNS Security: malware / ransomware / NRD | sinkhole/alert | T1105/T1486 | Threat log(s) |
| 4 | URL Filtering: high-risk | alert/block | T1608 | URL log |
| 5 | DNS Security: dns-infiltration / dns-tunnel | sinkhole | T1048/T1071.004 | Threat log(s) |
| 5 | DNS Security: proxy/anonymizer | alert/block | T1048 | Threat log |

**Cross-check on the firewall itself:** *Monitor ▸ Logs ▸ Threat* and *URL
Filtering* — you should see the same events with `action = sinkhole / block /
reset`. This is the definitive proof the **firewall** (not the agent) caught it.

XQL sanity check in Cortex:
```
dataset = panw_ngfw_threat_raw
| filter action in ("sinkhole","block-url","reset-both","drop")
| fields _time, misc, category, action, src_ip, dst_ip
| sort desc _time
```

See `docs\verification-checklist.md` for a printable tick-box version.

---

## 7. Safety, scope & cleanup

- **Nothing malicious.** Only Palo Alto's own benign test domains/pages are
  contacted; the optional EICAR is the standard AV *test* string, not a virus.
- **No persistence, no admin, no AD.** Scripts only make DNS lookups and HTTP
  GETs. `DryRun` prints every action without sending traffic.
- **Authorized labs only.** This is a detection/prevention demo for environments
  you own or are authorized to test.

---

## 8. Firewall-sourced vs agent-sourced (why this works)

When the same behaviour is visible to **both** the XDR agent and the firewall,
Cortex attributes the detection to the agent, because endpoint telemetry is
richer (it knows the *process*). That is why the earlier LDAP/Kerberos
behavioural demo showed up as **"XDR Analytics"** with descriptions like *"the
process powershell.exe executed 9 LDAP queries"* — a firewall EAL log can never
contain a process name, so those were agent detections.

**Firewall Threat-Prevention enforcement is different.** DNS sinkholing, URL
Filtering blocks and Antivirus resets are actions the *firewall* takes and logs
itself. The agent has no equivalent enforcement record to shadow them, so these
alerts are unambiguously **Palo Alto NGFW–sourced** in XSIAM — exactly what a
"firewall blocks" demo needs.

---

## 9. Optional: behavioural EAL analytics add-on

The original AD behavioural stages (Rare LDAP enumeration, Kerberoast, RPC
lateral movement) are preserved under `scripts/optional-ad-eal/`. They exercise
the **EAL-log analytics** detectors and need a real AD lab (DC + lateral target).
With an XDR agent on the source host these tend to be attributed to the endpoint
(see §8), so they are **not** part of the primary firewall demo — run them only
if you specifically want to show the behavioural-analytics layer *and* can use a
source host without the agent. See the headers in those scripts for details.
