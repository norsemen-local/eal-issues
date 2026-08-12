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

## 4. Safety
Benign DNS/HTTP only (dummy beacons to a lab attacker + made-up domains).
`DryRun` sends nothing. The recurring detectors are multi-day — a single run
seeds them; re-run across days for the full "recurring" signal.
