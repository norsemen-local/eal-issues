# Case 7 — Poisoned Well (Rogue Software-Update Hijack)

**Story.** A supply-chain-style intrusion. **Start:** the user is phished.
**Middle:** the attacker redirects the victim's software-update traffic to a
**rogue update server**, delivers a trojanized "update" over **plain HTTP**, and
an **unmanaged device model** shows up speaking the update protocol. **End:** the
fake update runs and beacons out to the attacker's rare C2 domain.

- **Roles:** Kali = rogue update server + C2; this Windows host = victim.
  Every stage is a **PAN Firewall EAL** log.
- New story case — see [`../README.md`](../README.md).

---

## 1. Attack flow → enabled EAL rules

```
  VICTIM ──MS-Update / HTTP──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR     ATTACKER=rogue update server
  (1) PHISHING ─▶ (2) rogue update server ─▶ (3) update over HTTP ─▶ (4) unmanaged model ─▶ (5) trojan C2
```

| # | Stage (arc) | What the victim does | EAL alert | Rule id | Technique |
|---|-------------|----------------------|-----------|---------|-----------|
| 1 | **Start — Initial Access** | Phishing / drive-by | Phishing site access + malware URL | *(URL Filtering)* | T1566 |
| 2 | **Middle — Update hijack** | WSUS/Windows-Update requests to a rare server | **Rare MS-Update Server was detected** | `3d068240` | T1199 |
| 3 | **Middle — Delivery** | Trojanized update over plain HTTP | **Rare MS-Update traffic over HTTP** | `a3602352` | T1210 |
| 4 | **Middle — Rogue device** | Unmanaged device model on the update protocol | **Unique client computer model via MS-Update protocol** | `59b720f1` | T1200 |
| 5 | **End — Payload C2** | Fake update beacons to a rare domain | **Abnormal Communication to a Rare Domain** | `c2da63d1` | T1071 |

---

## 2. Run it
```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 7 -DryRun
.\Invoke-AttackLifecycle.ps1 -Cases 7 -Live
```
Or standalone: **`case-7\Start-Demo.cmd`**. MS-Update traffic uses `http://` so
the firewall app-ID's it without decryption.

## 3. Expected in Cortex XSIAM / XDR
| Stage | Alert | Rule id |
|-------|-------|---------|
| 2 | Rare MS-Update Server was detected | `3d068240` |
| 3 | Rare MS-Update traffic over HTTP | `a3602352` |
| 4 | Unique client computer model via MS-Update protocol | `59b720f1` |
| 5 | Abnormal Communication to a Rare Domain | `c2da63d1` |

See [`docs/verification-checklist.md`](docs/verification-checklist.md).

## 4. Safety
Benign HTTP requests mimicking the update protocol (dummy payloads, no real
binaries). `DryRun` sends nothing. The "unmanaged device model" stage advertises
the model in request metadata — a best-effort approximation of the WSUS inventory
field. Authorized labs only.
