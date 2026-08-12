# EAL Demo — Case 2: External Web-Application Exploitation

An attacker probes and exploits an internet/DMZ-facing web application. The Palo
Alto Networks NGFW inspects the malicious HTTP as **EAL (Enhanced Application)
logs**, Cortex XSIAM/XDR raises the **web-attack analytics alerts**, and
Vulnerability Protection / URL Filtering can **block** the exploit attempts.

All requests are crafted to *look* malicious (so the firewall inspects and logs
them) but are **benign** — dummy payloads that don't actually exploit anything.

> One of the five demo cases. Each covers a **different, non-overlapping** set of
> EAL-log alerts. See `../README-cases.md` for the full matrix.

---

## 1. Attack flow → EAL alerts

```
  ATTACKER  ──HTTP──▶  PALO ALTO NGFW (EAL logs + Vuln Protection)  ──▶  WEB APP
                              │
                              └── EAL logs / threat logs ──▶ Cortex XSIAM/XDR
  (1) traversal ─▶ (2) Spring4Shell ─▶ (3) web-shell params ─▶ (4) rare UA ─▶ (5) covert HTTP
```

| # | Stage (ATT&CK tactic) | What the script sends | Enabled EAL alert | Rule id | Technique |
|---|----------------------|-----------------------|-------------------|---------|-----------|
| 1 | **Recon → Initial Access** (TA0007/TA0001) | Directory-traversal URIs (`../../etc/passwd`, `%2e%2e`) | **Possible path traversal via HTTP request** | `60da6e16` | T1083 |
| 2 | **INITIAL ACCESS** (TA0001) | Spring4Shell `class.module.classLoader...` payload | **Suspicious failed HTTP request - Spring4Shell** | `1028c23d` | T1190 |
| 3 | **Initial Access / Persistence** (TA0001/TA0003) | Web-shell params (`cmd=`, SSTI `{{7*7}}`, `php://filter`) | **Suspicious HTTP parameters detected** | `3508f6b4` | T1133 · T1505.003 |
| 4 | **Command & Control** (TA0011) | Rare/odd `User-Agent` strings to an external server | **Abnormal rare combination of HTTP User Agent and HTTP Server** | `c13fd72e` | T1102 · T1567 |
| 5 | **C2 / Exfiltration** (TA0011/TA0010) | Odd methods (PUT/PATCH), encoded data in headers/URI | **HTTP with suspicious characteristics** | `7fbfd969` | T1102 · T1567 |

The **initial access is the web exploitation itself** (stages 1–2): Spring4Shell
is a pattern-based, reliably-triggered EAL alert. Stages 1–3 are also enforced by
**Vulnerability Protection**, giving firewall **block** actions alongside the EAL
detections. Every alert maps to an **enabled** rule in your tenant.

---

## 2. Prerequisites

| Component | Requirement |
|-----------|-------------|
| Attacker host | One Windows box, PowerShell 5.1+. Agent installed is fine. |
| Web server | A lab web app reachable **through** the firewall (any HTTP server; it does not need to be vulnerable — the requests only need to traverse the firewall). Set `TargetWebServer`. |
| NGFW | Rule covering the host with **Vulnerability Protection** + **URL Filtering** profiles, **EAL enabled**, log forwarding to Cortex. |
| Cortex | XSIAM/XDR ingesting the firewall EAL/threat logs. |

Use `http://` targets so the firewall reads the URI/headers without decryption.

---

## 3. Run it

**Double-click `Start-Demo.cmd`** → **[1] Configure** (set your web server) →
**[2] Preflight → [3] Dry run → [4] Run**. Or manually:

```powershell
cd D:\PANW\eal-demo\case-2
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\00-preflight.ps1
.\scripts\Run-All.ps1 -DryRun
.\scripts\Run-All.ps1 -PauseBetween
```

`[BLOCK]` (magenta) = the firewall/server rejected the request (expected —
rejection is the signal); `[OK]` = the request went through and was logged.

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 | Possible path traversal via HTTP request | `60da6e16` | URI with `../` toward the web server |
| 2 (IA) | Suspicious failed HTTP request - Spring4Shell | `1028c23d` | `class.module.classLoader` in the request |
| 3 | Suspicious HTTP parameters detected | `3508f6b4` | web-shell-style query params |
| 4 | Abnormal rare combination of HTTP User Agent and HTTP Server | `c13fd72e` | odd User-Agent to external host |
| 5 | HTTP with suspicious characteristics | `7fbfd969` | odd method + encoded data |

Also check the NGFW **Monitor ▸ Logs ▸ Threat / URL Filtering** for
Vulnerability-Protection block actions on stages 1–3. XQL:
```
dataset = panw_ngfw_threat_raw | filter category contains "code-execution" or misc contains "traversal" | sort desc _time
```

See `docs/verification-checklist.md`.

---

## 5. Safety
Dummy payloads only — no real exploitation. Point `TargetWebServer` at a lab
server you own/are authorized to test. `DryRun` prints without sending.
