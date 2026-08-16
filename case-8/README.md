# Case 8 — The Departing Employee (Insider Data Heist)

**Story.** No phishing, no exploit — the access is legitimate. **Start:** a
soon-to-leave employee spends the day on job boards and personal/streaming sites
— the behavioural tell. **Middle:** they open an exfil channel to an FTP server
the org has never seen, logging in as an unusual user. **End:** a bulk upload of
(dummy) data to a rare personal cloud/mail service — the heist.

- **Roles:** the insider **is** the victim host; Kali = the external drop
  (FTP + upload endpoint). Every stage is a **PAN Firewall EAL** log.
- New story case — see [`../README.md`](../README.md).

---

## 1. Attack flow → EAL rules

```
  INSIDER(victim) ──web / FTP / upload──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR   DROP=Kali
  (1) job-hunt + time-consuming browsing ─▶ (2) new FTP / rare user ─▶ (3) massive upload
```

| # | Stage (arc) | What the insider does | EAL alert | Rule id | Technique |
|---|-------------|-----------------------|-----------|---------|-----------|
| 1 | **Start — intent/recon** | Visits many job boards + time-consuming sites | **Increase in Job-Related Site Visits** + **A user accessed multiple time-consuming websites** | *(enable if off)* | T1593 |
| 2 | **Middle — staging** | Logs into a new/rare FTP server as an unusual user | **New FTP Server** + **A rare FTP user has been detected** | `ce208ea2`, `df8fa99b` | T1213 · T1078 |
| 3 | **End — exfiltration** | Bulk upload to a rare storage/mail domain | **Massive upload to a rare storage or mail domain** | *(enable if off)* | T1567.002 |

> Stage 2 uses **enabled** rules (`ce208ea2`, `df8fa99b`). Stages 1 & 3 use
> behavioural insider/exfil detectors that may need enabling in your tenant —
> the traffic still generates regardless; the alerts appear once the detectors
> are on.

## The XDR endpoint layer (the other half of the story)

| Stage | Endpoint action | XDR analytic |
|-------|-----------------|-------------|
| 2 | compress files into a staging archive | *Suspicious file created* / data staging (T1560) |

**Story:** no malware — the insider stages stolen files into an archive
(endpoint), then opens a new/rare FTP channel and bulk-uploads to a personal
cloud (network). Living-off-the-land, which is exactly why the combined
endpoint+network view matters.

---

## Detection model
Stage 2 (FTP) uses enabled rules and fires reliably. Stage 3 also resolves
category-matched **DNS-Security test domains** (`test-dns-infiltration`,
`test-proxy` `.testpanw.com`) → an **instant PAN NGFW** detection, so the exfil
stage lights up the firewall even if the behavioural "massive upload" and
insider-browsing detectors (baseline / may need enabling) haven't fired yet.

---

## 2. Run it
```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 8 -DryRun
.\Invoke-AttackLifecycle.ps1 -Cases 8 -Live
```
Or standalone: **`case-8\Start-Demo.cmd`**.

## 3. Expected in Cortex XSIAM / XDR
| Stage | Alert | Rule id |
|-------|-------|---------|
| 1 | Increase in Job-Related Site Visits + multiple time-consuming websites | *(enable if off)* |
| 2 | New FTP Server + A rare FTP user | `ce208ea2`, `df8fa99b` |
| 3 | Massive upload to a rare storage or mail domain | *(enable if off)* |

See [`docs/verification-checklist.md`](docs/verification-checklist.md).

## 4. Real vs simulated — will the FW / XDR agent actually recognise this?

**Legend** — ✅ **REAL·instant (FW)**: signature/category, fires first-run. 🟡
**REAL·baseline (EAL)**: genuine traffic the analytic models, fires only after the
baseline matures / the detector is enabled. 🔵 **REAL·endpoint (XDR agent BIOC)**:
real host action the agent observes. 🟠 **SIMULATED**: approximation only.

Every stage sends **real traffic** in Live mode — nothing here is print-only. The
subtlety is destination *categorisation* and which detectors are enabled.

| # | Stage | What the code ACTUALLY sends | Detection | Class | Source |
|---|-------|------------------------------|-----------|-------|--------|
| 1 | Job-hunt + time-consuming browsing | Real HTTPS GETs to 6 live job boards (LinkedIn/Indeed/Glassdoor/Monster/ZipRecruiter/Dice) + 6 streaming/social sites — genuinely categorisable via SNI | Increase in Job-Related Site Visits + multiple time-consuming sites (T1593) | 🟡 **REAL·baseline** (*enable if off*) | FW (EAL) |
| 2e | Data staging (endpoint) | **Real** random `.bin` files `Compress-Archive`'d into a ~5 MB zip in %TEMP% (label says 25 MB; code writes ~5) | Suspicious file created / data staging (T1560) | 🔵 **REAL·endpoint** | XDR agent (BIOC) |
| 2 | New / rare FTP channel | **Real** `FtpWebRequest` logins to the attacker IP as `leaver_x`, `anonymous`, `leaver_x_bak` | New FTP Server `ce208ea2` + rare FTP user `df8fa99b` | 🟡 **REAL·baseline** (these two are enabled) | FW (EAL) |
| 3 | Massive upload | **Real** 45 MB random blob HTTP-POSTed to `personal-cloud-drop.net/upload` + the attacker IP **+** `test-dns-infiltration` / `test-proxy`.testpanw.com | Massive upload to rare storage/mail (T1567.002) (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (*enable if off*) · exact detector may miss (see below) · **+ ✅ anchor** | FW (EAL / DNS-Sec) |

**Bottom line:** the reliable signals are stage 2's FTP rules (enabled, near
real-time) and stage 3's `test-*.testpanw.com` DNS-Security hits (instant). The 45
MB upload is **genuinely transmitted**, but `personal-cloud-drop.net` is a
fabricated domain that won't resolve and is **not categorised as online-storage /
webmail**, so the exact "Massive upload to a rare storage or mail domain" detector
may not match — point the destination at a real categorised storage host if you
need that specific rule. Stage 1's sites are real and correctly categorised, but
the named insider-browsing analytics are baseline detectors that **may be off** —
enable T1593 / T1567.002 in the tenant. If an XDR agent is on the host, the staging
zip raises a data-staging BIOC.

---

## 5. Safety
Stage 1 visits real, benign job/streaming sites (normal web browsing). Exfil is a
dummy random blob to your lab drop. `DryRun` sends nothing. For stage 3 the
destination should categorise as online-storage/webmail for the exact detector;
by default it points at your attacker host. Authorized labs only.
