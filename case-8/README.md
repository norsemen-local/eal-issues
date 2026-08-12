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

## 4. Safety
Stage 1 visits real, benign job/streaming sites (normal web browsing). Exfil is a
dummy random blob to your lab drop. `DryRun` sends nothing. For stage 3 the
destination should categorise as online-storage/webmail for the exact detector;
by default it points at your attacker host. Authorized labs only.
