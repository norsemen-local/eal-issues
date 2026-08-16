# Case 6 — Ghost in the DNS (Resilient / Evasive C2)

**Story.** A phished endpoint quietly builds a *resilient, evasive* command
channel. **Start:** the user is lured to the attacker (phishing). **Middle:** the
implant fuzzes subdomains to find live C2 nodes, rotates through throwaway
dynamic-DNS domains, and hides its beacons behind an odd TLS + User-Agent
fingerprint. **End:** it settles into a slow, recurring beacon to a rare malware
domain — a long-haul channel that survives takedowns.

- **Roles:** Kali = attacker/C2; this Windows host = victim. Traffic is
  victim → attacker / DNS. Every stage is a **PAN Firewall EAL** log.
- New story case — see [`../README.md`](../README.md).

---

## 1. Attack flow → enabled EAL rules

```
  VICTIM ──DNS/HTTP(S)──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR        ATTACKER=C2
  (1) PHISHING ─▶ (2) subdomain fuzz ─▶ (3) dyn-DNS rotate ─▶ (4) rare TLS/UA ─▶ (5) recurring rare-domain
```

| # | Stage (arc) | What the victim does | EAL alert | Rule id | Technique |
|---|-------------|----------------------|-----------|---------|-----------|
| 1 | **Start — Initial Access** | Phishing / drive-by (victim → attacker) | Phishing site access + malware URL | *(URL Filtering)* | T1566 |
| 2 | **Middle — Recon** | Fuzzes 60 subdomains of one root | **Subdomain Fuzzing** | `fdcaa14c` | T1595.003 |
| 3 | **Middle — C2 resilience** | Recurring access to dynamic-DNS domains | **Recurring rare domain access to dynamic DNS domain** | `00977673` | T1568 |
| 4 | **Middle — C2 evasion** | Beacons with a rare TLS + User-Agent pairing | **Abnormal rare combination of TLS and HTTP User Agent** | `7f213d7d` | T1102 · T1567 |
| 5 | **End — Persistent C2** | Slow recurring beacon to a rare malware domain | **Recurring access to rare domain** (+ `c2dbeac4`) | `8c2e83de` | T1071 |

## The XDR endpoint layer (the other half of the story)

The victim host also performs endpoint actions the **XDR agent** detects, so the
XSIAM case stitches **endpoint + network** into one incident:

| Stage | Endpoint action | XDR analytic |
|-------|-----------------|-------------|
| 2 | base64 PowerShell + `certutil` LOLBIN download + AppData drop | *PowerShell runs base64-encoded commands*; *LOLBIN/scripting engine connected to a rare external host*; *Suspicious file created in AppData directory* |
| 5 | HKCU Run-key | *Script file added to startup-related Registry keys* |

**Story:** a fileless PowerShell implant lands (base64 exec + certutil stager +
AppData drop), discovers C2 via subdomain fuzzing / dyn-DNS, beacons with a rare
TLS+UA, and persists via a Run-key while recurring to a rare domain.

---

## Detection model (read this)

Each stage fires **two** kinds of detection:

1. **Firewall anchor (reliable, instant, PAN NGFW):** every stage resolves a
   category-matched Palo Alto **DNS-Security test domain** (`test-c2`,
   `test-dga`, `test-ddns`, `test-fastflux`, `test-subdomain-reputation`,
   `test-strategically-aged` `.testpanw.com`). These fire an **immediate,
   firewall-sourced** DNS threat detection — **no baseline required** — so the
   firewall lights up at every step even in a fresh tenant.
2. **Behavioural EAL analytic (bonus, delayed):** the rules in the table
   (`fdcaa14c`, `00977673`, `7f213d7d`, `8c2e83de`) are **baseline** detectors —
   the docs specify a **30-day training + 14-day activation** window. They will
   **not** fire on a first run; they surface only after the firewall has learned
   the host's normal behaviour (and can be shadowed by the XDR agent). Treat them
   as the "matures over time" layer, not the demo backbone.

> This is the fix for "I only saw XDR agent BIOCs": the DNS-Security anchors give
> you real **PAN NGFW** detections per stage immediately, instead of waiting on
> baseline analytics that the endpoint agent out-races.

---

## 2. Run it
```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 6 -DryRun     # rehearse
.\Invoke-AttackLifecycle.ps1 -Cases 6 -Live       # run
```
Or standalone: **`case-6\Start-Demo.cmd`** → **[2] → [3] → [4]**.

## 3. Expected in Cortex XSIAM / XDR
| Stage | Alert | Rule id |
|-------|-------|---------|
| 2 | Subdomain Fuzzing | `fdcaa14c` |
| 3 | Recurring rare domain access to dynamic DNS domain | `00977673` |
| 4 | Abnormal rare combination of TLS and HTTP User Agent | `7f213d7d` |
| 5 | Recurring access to rare domain / Abnormal Recurring Communications | `8c2e83de`, `c2dbeac4` |

See [`docs/verification-checklist.md`](docs/verification-checklist.md).

## 4. Real vs simulated — will the FW / XDR agent actually recognise this?

**Legend** — ✅ **REAL·instant (FW)**: signature/category, fires first-run. 🟡
**REAL·baseline (EAL)**: genuine traffic the analytic models, fires only after the
baseline matures. 🔵 **REAL·endpoint (XDR agent BIOC)**: real host action the agent
observes, mostly same-run. 🟠 **SIMULATED**: approximation only.

| # | Stage | What the code ACTUALLY sends | Detection | Class | Source |
|---|-------|------------------------------|-----------|-------|--------|
| 1 | Phishing / drive-by IA | Real GETs to PANW URL-Filtering test pages + attacker-IP fetch | Phishing/malware URL categorisation | ✅ **REAL·instant** | FW (URL Filtering) |
| 2 | Subdomain fuzzing | 60 real DNS lookups of `<word><i>.ghost-c2-demo.net` **+** `test-subdomain-reputation` / `test-dga`.testpanw.com | Subdomain Fuzzing `fdcaa14c` (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (+ ✅ anchor) | FW (EAL / DNS-Sec) |
| 2e | Endpoint implant | **Real**: `powershell -EncodedCommand`, AppData drop, `certutil.exe` LOLBIN fetch from the attacker | Encoded PowerShell; LOLBIN→rare host; Suspicious AppData file | 🔵 **REAL·endpoint** | XDR agent (BIOC) |
| 3 | Dyn-DNS rotation | Real DNS + `GET /gate.php` to duckdns/no-ip/hopto/ddns **+** `test-ddns` / `test-fastflux`.testpanw.com | Recurring dyn-DNS `00977673` (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (multi-day) (+ ✅ anchor) | FW (EAL / DNS-Sec) |
| 4 | Rare TLS + UA | Real TLS to `https://<attacker>/tls-beacon` with odd UA headers **+** `test-c2`.testpanw.com. *(UA is real; JA3 is PowerShell's default, not crafted.)* | Rare TLS+UA combo `7f213d7d` (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (+ ✅ anchor) | FW (EAL / DNS-Sec) |
| 5 | Recurring rare-domain C2 | 12 real DNS + `GET /checkin` to `recurring-rare-c2-demo.net` **+** `test-strategically-aged` / `test-c2`.testpanw.com | Recurring rare domain `8c2e83de` (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (multi-day) (+ ✅ anchor) | FW (EAL / DNS-Sec) |
| 5e | Startup persistence | **Real** HKCU `...\Run` key write (auto-reverted) | Script added to startup Run key | 🔵 **REAL·endpoint** | XDR agent (BIOC) |

**Bottom line:** **no simulated-only stages.** On the first run you get the instant
firewall layer (URL-Filtering + six DNS-Security categories) **and** the endpoint
BIOCs on stages 2 & 5 (real encoded-PowerShell / certutil / Run-key actions, if an
XDR agent is on the victim). The four named DNS behavioural analytics (`fdcaa14c`,
`00977673`, `7f213d7d`, `8c2e83de`) are genuine traffic but **baseline-dependent**
and multi-day for the "recurring" ones — a single run only seeds them. The nearest
thing to an approximation is stage 4's TLS: the connection and odd User-Agent are
real, but it does not craft a custom JA3 (it uses .NET's default stack).

---

## 5. Safety
Benign DNS/HTTP only (dummy beacons to a lab attacker + made-up domains).
`DryRun` sends nothing. The recurring detectors are multi-day — a single run
seeds them; re-run across days for the full "recurring" signal.
