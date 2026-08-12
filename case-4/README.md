# Case 4 — Phishing Foothold → Identity Compromise & AD Domination

**Lifecycle:** a Windows **victim** is phished, then the compromised host attacks
Active Directory — enumerates via LDAP, poisons WPAD to capture credentials,
coerces the domain controller (PetitPotam/EFSRPC), replicates secrets (DCSync),
and abuses Kerberos delegation (Bronze Bit). The Palo Alto NGFW logs the auth
traffic as **EAL logs**; Cortex XSIAM/XDR (ITDR) raises the alerts.

- **Roles:** Kali = attacker / C2 (`AttackerC2`) for the phishing entry; this
  Windows host = victim (runs the scripts); the **DC** is the identity target.
- Needs **ITDR / Identity Analytics** enabled in Cortex.
- One of five cases — see [`../README.md`](../README.md).

---

## 1. Attack flow → enabled EAL rules

```
   (1) PHISHING ─▶ (2) LDAP enum ─▶ (3) WPAD ─▶ (4) EFSRPC ─▶ (5) DCSync ─▶ (6) Bronze Bit
   VICTIM(Windows) ──LDAP / NTLM / Kerberos / MSRPC──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR
```

| # | Stage (ATT&CK tactic) | What the victim does | Enabled EAL alert | Rule id | Technique |
|---|----------------------|----------------------|-------------------|---------|-----------|
| 1 | **INITIAL ACCESS** (TA0001) | Phishing / drive-by (victim → attacker) | **Phishing site access** + malware URL (URL Filtering) | *(URL Filtering)* | T1566 · T1204 |
| 2 | **Discovery** (TA0007) | Rare combination of AD/LDAP queries | **Rare LDAP enumeration** | `fcb12ef3` | T1087 |
| 3 | **Credential Access** (TA0006) | Repeated WPAD resolves + `wpad.dat` fetches | **Uncommon WPAD queries** | `f1546fee` | T1557 |
| 4 | **Credential Access** (TA0006) | EFSRPC named-pipe coercion to the DC (PetitPotam) | **Suspicious EFSRPC to domain controller** | `82a37634` | T1550.002 |
| 5 | **Credential Access** (TA0006) | Directory-replication RPC to the DC from a non-DC | **Possible DCSync from a non domain controller** | `b00baad9` | T1003.006 |
| 6 | **Credential Access** (TA0006) | Kerberos S4U / delegation ticket requests | **Bronze-Bit exploit** | `115c6f43` | T1204 |

---

## 2. Prerequisites
- Windows victim, PowerShell 5.1+, domain-joined.
- The **DC** reachable (LDAP/SMB/Kerberos) through the PAN NGFW (EAL + log
  forwarding); **ITDR / Identity Analytics** enabled in Cortex.
- Optional tools for the exact exploit: `PetitPotam.exe` / `mimikatz` / `Rubeus`
  in `scripts\tools\` — the native stages generate the traffic and note the tool.

---

## 3. Run it

```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 4 -Domain corp.local -DomainController DC01.corp.local -Live
```
Or standalone: **`case-4\Start-Demo.cmd`** → **[1] Configure** (attacker/C2,
domain, DC) → **[2] → [3] → [4]**. Failed coercions/logins are the point — the
scripts warn and continue; the failed-auth / RPC traffic is what the firewall logs.

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 | Phishing site access + malware URL | *(URL Filtering)* | victim → phishing/malware URL |
| 2 | Rare LDAP enumeration | `fcb12ef3` | unusual LDAP query combination to the DC |
| 3 | Uncommon WPAD queries | `f1546fee` | repeated WPAD lookups from the victim |
| 4 | Suspicious EFSRPC to domain controller | `82a37634` | EFSRPC/MSRPC to the DC |
| 5 | Possible DCSync from a non domain controller | `b00baad9` | replication RPC to the DC from a non-DC |
| 6 | Bronze-Bit exploit | `115c6f43` | forwardable Kerberos ticket for a Protected User |

See [`docs/verification-checklist.md`](docs/verification-checklist.md).

---

## 5. Safety
Phishing uses benign test pages; failed logins, WPAD lookups, named-pipe /
replication RPC, and normal ticket requests only. EFSRPC/DCSync/Bronze-Bit are
best-effort natively and flag the tool required for the exact exploit. Authorized
labs only. `DryRun` sends nothing.
