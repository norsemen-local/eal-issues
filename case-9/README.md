# Case 9 — Pass-the-Hash Playbook (NTLM Relay & Kerberos Downgrade)

**Story.** An authentication-abuse campaign. **Start:** the user is phished.
**Middle:** the attacker probes with malformed logins, forces first-time NTLM,
authenticates as a machine account, and downgrades Kerberos to weak RC4 tickets.
**End:** it reaches the ADFS configuration store from a non-ADFS host — the setup
for a Golden SAML token forgery that owns the federation.

- **Roles:** Kali = attacker/C2 (phishing entry); this Windows host = victim;
  the **DC / ADFS** are the identity targets. Every stage is a **PAN Firewall
  EAL** log (ITDR).
- New story case — see [`../README.md`](../README.md).

---

## 1. Attack flow → EAL rules

```
   (1) PHISHING ─▶ (2) long-user + NTLM ─▶ (3) machine NTLM ─▶ (4) RC4 Kerberos ─▶ (5) ADFS sync
   VICTIM ──NTLM / Kerberos / MSRPC / HTTP──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR (ITDR)
```

| # | Stage (arc) | What the victim does | EAL alert | Technique |
|---|-------------|----------------------|-----------|-----------|
| 1 | **Start — Initial Access** | Phishing / drive-by | Phishing site access + malware URL | T1566 |
| 2 | **Middle — Cred Access** | Malformed long-username logins + first-time NTLM (by IP) | **Failed Login For a Long Username With Special Characters** + **Rare NTLM Usage by User** | T1190 · T1550 |
| 3 | **Middle — Cred Access** | NTLM as a machine account | **Suspicious NTLM authentication with machine account** | T1187 |
| 4 | **Middle — Cred Access** | RC4 (etype 23) Kerberos ticket requests | **Weakly-Encrypted Kerberos TGT Response** | T1556.001 |
| 5 | **End — Federation** | ADFS policy-store sync from a non-ADFS host | **Unusual ADFS Remote Synchronization ... from non-ADFS server** | T1606.002 |

> These are **identity/ITDR** detectors — enable **ITDR / Identity Analytics** and
> the individual rules in your tenant if they aren't already on. The traffic
> generates regardless; the alerts appear once the detectors are active.

---

## 2. Run it
```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 9 -Domain corp.local -DomainController DC01.corp.local -Live
```
Or standalone: **`case-9\Start-Demo.cmd`** → **[1] Configure** (attacker, DC,
ADFS, auth target) → **[2] → [3] → [4]**. Stage 3 is most accurate **run as
SYSTEM** (`PsExec -s`).

## 3. Expected in Cortex XSIAM / XDR
| Stage | Alert | Technique |
|-------|-------|-----------|
| 2 | Failed Login For a Long Username + Rare NTLM Usage by User | T1190 · T1550 |
| 3 | Suspicious NTLM authentication with machine account | T1187 |
| 4 | Weakly-Encrypted Kerberos TGT Response | T1556.001 |
| 5 | Unusual ADFS Remote Synchronization from non-ADFS server | T1606.002 |

See [`docs/verification-checklist.md`](docs/verification-checklist.md).

## 4. Safety
Failed logins, first-time NTLM, normal (RC4) ticket requests, and ADFS endpoint
connections only — no credential theft. `DryRun` sends nothing. Stage 3 needs
SYSTEM context for the exact machine-account signal. Authorized labs only.
