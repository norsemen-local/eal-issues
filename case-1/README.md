# EAL Demo — Case 1: Drive-by to Data Theft (Malware C2 & Exfil)

A complete intrusion, start to finish: the attacker **breaches a public-facing
web app (Initial Access)**, the implant beacons out over DGA domains and DNS
tunneling, makes suspicious/failed DNS lookups, and exfiltrates to a rarely-seen
domain. The Palo Alto NGFW logs it as **EAL logs**; Cortex XSIAM/XDR raises the
analytics alerts; and (bonus) DNS Security **sinkholes/blocks** the test domains
woven in — so the same run shows **detect *and* block**.

> One of five demo cases (see `../README-cases.md`). Every stage maps to an
> **enabled** EAL rule in your tenant, and each case opens with a clear,
> reliably-triggered **Initial Access**.

---

## 1. Attack flow → enabled EAL rules

```
  ATTACKER ──▶ PALO ALTO NGFW (EAL) ──▶ Cortex XSIAM/XDR
   (1) WEB BREACH ─▶ (2) DGA ─▶ (3) DNS tunnel ─▶ (4) odd DNS ─▶ (5) rare-domain exfil
```

| # | Stage (ATT&CK tactic) | What the script does | Enabled EAL alert | Rule id | Technique |
|---|----------------------|----------------------|-------------------|---------|-----------|
| 1 | **INITIAL ACCESS** (TA0001) | Spring4Shell + traversal against the public web app | **Suspicious failed HTTP request - Spring4Shell** | `1028c23d` | T1190 |
| 2 | **C2** (TA0011) | 45 random-looking domain lookups (DGA) | **Random-Looking Domain Names** | `ce6ae037` | T1568.002 |
| 3 | **C2 / Exfil** (TA0011) | >10 KB encoded into DNS subdomains | **DNS Tunneling** | `61a5263c` | T1071.004 |
| 4 | **C2** (TA0011) | Malformed / non-existent DNS lookups | **Suspicious DNS traffic** + **Failed DNS** | `2a77fad6`, `74c65024` | T1071.004 |
| 5 | **EXFILTRATION** (TA0010) | Repeated comms to a rarely-seen domain | **Abnormal Communication to a Rare Domain** | `c2da63d1` | T1567 |

**Firewall block layer (bonus):** stages 2/3/5 also query PANW DNS-Security test
domains (`test-dga`, `test-dnstun`, `test-dns-infiltration` `.testpanw.com`) so
the firewall **sinkholes/blocks** them — visible in Monitor ▸ Logs ▸ Threat.

---

## 2. Prerequisites

| Component | Requirement |
|-----------|-------------|
| Attacker host | One Windows box, PowerShell 5.1+. Agent installed is fine. |
| Web server (IA) | A lab web server reachable **through** the firewall (`TargetWebServer`, http://). It need not be vulnerable — the request pattern is what fires the alert. |
| NGFW | EAL enabled + DNS Security & URL/Vuln profiles + log forwarding to Cortex; DNS + HTTP egress traverses the firewall. |
| Cortex | XSIAM/XDR ingesting the firewall EAL logs; rules above enabled. |

---

## 3. Run it

**Double-click `Start-Demo.cmd`** → **[1] Configure** (web server + domains) →
**[2] Preflight → [3] Dry run → [4] Run**. Or:

```powershell
cd D:\PANW\eal-demo\case-1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\00-preflight.ps1
.\scripts\Run-All.ps1 -DryRun
.\scripts\Run-All.ps1 -PauseBetween
```

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 | Suspicious failed HTTP request - Spring4Shell | `1028c23d` | `class.module.classLoader` request to the web server |
| 2 | Random-Looking Domain Names | `ce6ae037` | many random root domains from the host |
| 3 | DNS Tunneling | `61a5263c` | >10 KB under `tunnel.<DgaRootDomain>` |
| 4 | Suspicious DNS traffic / Failed DNS | `2a77fad6` / `74c65024` | malformed / NXDOMAIN lookups |
| 5 | Abnormal Communication to a Rare Domain | `c2da63d1` | recurring hits to the rare domain |

Firewall block proof: **Monitor ▸ Logs ▸ Threat** shows the `test-*.testpanw.com`
DNS Security sinkholes. See `docs/verification-checklist.md`.

---

## 5. Safety
Dummy Spring4Shell pattern (no real RCE), benign DNS lookups, PANW test domains.
`DryRun` sends nothing. Authorized labs only.
