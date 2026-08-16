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

## 5. Real vs simulated — will the FW / XDR agent actually recognise this?

**Legend** — ✅ **REAL·instant (FW)**: signature/category, fires first-run, usually
blocks. 🟡 **REAL·baseline (EAL)**: genuine traffic the analytic models, fires only
after the baseline matures. 🟠 **SIMULATED**: approximation only.

This is the **strongest "real" case in the repo.** Every stage transmits authentic
malicious HTTP over the wire — the exploit *strings* are the real ones, so PAN
Vulnerability Protection and the web-attack analytics genuinely match them. The
only thing "benign" is the *effect*: the payloads don't achieve RCE and the target
may be an unrelated host. A block/reset/4xx is treated as success — the rejected
request is the signal.

| # | Stage | What the code ACTUALLY sends | Detection | Class | Source |
|---|-------|------------------------------|-----------|-------|--------|
| 1 | Path traversal | Real GETs with `../../../../etc/passwd`, `..%2f`, `....//` | Possible path traversal `60da6e16` | ✅ **REAL·instant** (+ Vuln-Protection block) | FW |
| 2 | Spring4Shell | GET + POST carrying the genuine `class.module.classLoader.resources.context.parent.pipeline.first.pattern` CVE-2022-22965 payload | Spring4Shell `1028c23d` | ✅ **REAL·instant** (+ Vuln-Protection block) | FW |
| 3 | Web-shell / suspicious params | `cmd=whoami`, `<?php system()?>`, `{{7*7}}` SSTI, `php://filter` | Suspicious HTTP parameters `3508f6b4` | ✅ **REAL·instant** (content/pattern) | FW |
| 4 | Rare UA + Server | 6 GETs to `/beacon` with odd User-Agents (MSIE5/Win98, python-requests-c2, Nim/Go stagers) | Rare HTTP UA+Server combo `c13fd72e` | 🟡 **REAL·baseline** | FW |
| 5 | Covert HTTP channel | Real `PUT /upload`, `PATCH /api`, `GET /pixel.gif?d=<b64>` with base64 in `X-Session-Data` + gif content-type mismatch | HTTP with suspicious characteristics `7fbfd969` | 🟡 **REAL·baseline** | FW |

**Bottom line:** stages 1–3 fire on the **first request** and produce
Vuln-Protection **block/reset** entries in Monitor ▸ Threat — the best live proof
in the whole repo. Stages 4–5 are real C2/exfil-shaped HTTP that the rare-UA and
HTTP-anomaly analytics only surface once their baseline matures. **No stage is
simulated-only.** These are all firewall-sourced network detections — an XDR
endpoint agent adds nothing here (no web shell is actually written), so ignore the
aspirational "(or XDR agent)" comments in the code. As shipped, the PowerShell
stages run **victim → target** (the inbound Kali `attack-web.sh` is the alternate
driver); detection only needs the request to *traverse* the firewall.

---

## 6. Safety
Dummy payloads only — no real exploitation. Attack a lab web server you own /
are authorized to test. `DryRun` sends nothing.
