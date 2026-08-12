# Case 2 — External Exploitation of a Public Web App (attacker-driven)

**Lifecycle:** the **attacker** (Kali) actively exploits the **victim's**
public-facing web application — directory traversal, a Spring4Shell attempt, and
web-shell parameter injection. The Palo Alto NGFW inspects the inbound HTTP as
**EAL logs**, Cortex XSIAM/XDR raises the web-attack analytics, and Vulnerability
Protection can **block** the exploit.

- **Roles:** Kali = attacker (source of the exploits); the web server being
  attacked = victim. This is the one **attacker → victim** (inbound) case.
- All requests are crafted to *look* malicious but are **benign** — dummy payloads.
- One of five cases — see [`../README.md`](../README.md).

---

## 1. Attack flow → enabled EAL rules

```
  ATTACKER(Kali) ──HTTP exploit──▶ PAN NGFW (EAL + Vuln Protection) ──▶ VICTIM web app
                                          │
                                          └── EAL / threat logs ──▶ Cortex XSIAM/XDR
   (1) traversal ─▶ (2) Spring4Shell ─▶ (3) web-shell params ─▶ (4) rare UA ─▶ (5) covert HTTP
```

| # | Stage (ATT&CK tactic) | What the attacker sends | Enabled EAL alert | Rule id | Technique |
|---|----------------------|-------------------------|-------------------|---------|-----------|
| 1 | **Recon → Initial Access** (TA0007/TA0001) | Directory-traversal URIs (`../../etc/passwd`, `%2e%2e`) | **Possible path traversal via HTTP request** | `60da6e16` | T1083 |
| 2 | **INITIAL ACCESS** (TA0001) | Spring4Shell `class.module.classLoader...` payload | **Suspicious failed HTTP request - Spring4Shell** | `1028c23d` | T1190 |
| 3 | **Initial Access / Persistence** (TA0001/TA0003) | Web-shell params (`cmd=`, SSTI `{{7*7}}`, `php://filter`) | **Suspicious HTTP parameters detected** | `3508f6b4` | T1133 · T1505.003 |
| 4 | **Command & Control** (TA0011) | Rare/odd `User-Agent` to an external server | **Abnormal rare combination of HTTP User Agent and HTTP Server** | `c13fd72e` | T1102 · T1567 |
| 5 | **C2 / Exfiltration** (TA0011/TA0010) | Odd methods (PUT/PATCH), encoded data in headers/URI | **HTTP with suspicious characteristics** | `7fbfd969` | T1102 · T1567 |

Stages 1–3 are also enforced by **Vulnerability Protection**, giving firewall
**block** actions alongside the EAL detections.

---

## 2. Prerequisites
- The Kali attacker box up with `attacker/attack-web.sh` present
  (the orchestrator's `-Provision` copies it, or `scp` it manually).
- A **web listener on the victim** so the inbound exploit sessions complete — the
  orchestrator starts a temporary one; or point at any lab web server.
- Kali must be able to **route to the victim** on the listener port (through the
  NGFW). EAL enabled + Vuln-Protection/URL profiles + log forwarding to Cortex.

---

## 3. Run it

Attacker-driven, via the global orchestrator (starts the victim listener, then
has Kali run `attack-web.sh`):
```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 2 -DryRun     # show the plan
.\Invoke-AttackLifecycle.ps1 -Cases 2 -Live       # attacker exploits the victim
# override the port / victim IP if needed:
.\Invoke-AttackLifecycle.ps1 -Cases 2 -Live -WebPort 8000 -VictimIP 10.0.0.50
```
On Kali directly: `bash /tmp/attack-web.sh http://<victim>:<port>`.

**Standalone fallback** (victim-outbound, when Kali can't route back to the
victim): `case-2\Start-Demo.cmd` runs the same requests from the Windows host to
a web target you set — still produces the EAL alerts, just with the victim as the
source.

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 | Possible path traversal via HTTP request | `60da6e16` | URI with `../` toward the web server |
| 2 (IA) | Suspicious failed HTTP request - Spring4Shell | `1028c23d` | `class.module.classLoader` in the request |
| 3 | Suspicious HTTP parameters detected | `3508f6b4` | web-shell-style query params |
| 4 | Abnormal rare combination of HTTP User Agent and HTTP Server | `c13fd72e` | odd User-Agent to external host |
| 5 | HTTP with suspicious characteristics | `7fbfd969` | odd method + encoded data |

Firewall block proof: **Monitor ▸ Logs ▸ Threat** — Vuln-Protection resets on
traversal / Spring4Shell / code-injection. See
[`docs/verification-checklist.md`](docs/verification-checklist.md).

---

## 5. Safety
Dummy payloads only — no real exploitation. Attack a lab web server you own /
are authorized to test. `DryRun` sends nothing.
