# Case 10 — Tunnels & Shadows (Covert Ops & Persistence)

**Story.** A quiet, tunnel-heavy intrusion. **Start:** the user is phished.
**Middle:** the implant opens an uncommon SSH session on a non-standard port,
turns it into a long high-volume tunnel for exfil, and hides extra beacons among
connections to obscure advertising domains. **End:** it plants persistence by
creating a scheduled task on a remote host over RPC.

- **Roles:** Kali = attacker / SSH-tunnel endpoint; this Windows host = victim;
  a remote host is the persistence target. Every stage is a **PAN Firewall EAL**
  log.
- New story case — see [`../README.md`](../README.md).

---

## 1. Attack flow → EAL rules

```
   (1) PHISHING ─▶ (2) uncommon SSH ─▶ (3) SSH tunnel volume ─▶ (4) rare ad domains ─▶ (5) remote schtask
   VICTIM ──SSH / DNS / HTTP / MSRPC──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR
```

| # | Stage (arc) | What the victim does | EAL alert | Rule id | Technique |
|---|-------------|----------------------|-----------|---------|-----------|
| 1 | **Start — Initial Access** | Phishing / drive-by | Phishing site access + malware URL | *(URL Filtering)* | T1566 |
| 2 | **Middle — Covert channel** | SSH session to a non-standard port | **Uncommon SSH session was established** | `18f84dd7` | T1071 · T1571 |
| 3 | **Middle — Covert channel** | Long, high-volume SSH tunnel | **Unusual SSH Activity** | `f1545c54` | T1572 |
| 4 | **Middle — Stealth C2** | Many connections to obscure ad domains | **Rare access to known advertising domains** | *(enable if off)* | T1071 · T1176.001 |
| 5 | **End — Persistence** | Remote scheduled task via RPC | **Rare Scheduled Task RPC activity from a rarely seen host** | *(enable if off)* | T1053 |

> Stages 2–3 use **enabled** SSH rules. Stages 4–5 use detectors that may need
> enabling in your tenant — the traffic generates regardless.

---

## 2. Run it
```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 10 -Live
```
Or standalone: **`case-10\Start-Demo.cmd`** → **[1] Configure** (attacker, SSH
port, remote host) → **[2] → [3] → [4]**. Stage 5 needs admin on the remote host.

## 3. Expected in Cortex XSIAM / XDR
| Stage | Alert | Rule id |
|-------|-------|---------|
| 2 | Uncommon SSH session was established | `18f84dd7` |
| 3 | Unusual SSH Activity | `f1545c54` |
| 4 | Rare access to known advertising domains | *(enable if off)* |
| 5 | Rare Scheduled Task RPC activity from a rarely seen host | *(enable if off)* |

See [`docs/verification-checklist.md`](docs/verification-checklist.md).

## 4. Safety
SSH banner/tunnel traffic to your lab attacker, benign DNS/HTTP to made-up ad
domains, and a create-then-delete remote task. `DryRun` sends nothing. Authorized
labs only.
