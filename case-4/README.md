# EAL Demo — Case 4: Identity Compromise & AD Domination

A complete identity-attack chain: the attacker **brute-forces an exposed service
(Initial Access)**, enumerates Active Directory, poisons WPAD to capture
credentials, coerces the domain controller (PetitPotam/EFSRPC), replicates
secrets (DCSync), and abuses Kerberos delegation (Bronze Bit). The Palo Alto NGFW
logs the auth traffic as **EAL logs**; Cortex XSIAM/XDR (ITDR) raises the alerts.

> One of five demo cases (see `../README-cases.md`). Every stage maps to an
> **enabled** EAL rule. Needs **ITDR / Identity Analytics** enabled in Cortex.

---

## 1. Attack flow → enabled EAL rules

```
   (1) FTP BRUTE ─▶ (2) LDAP enum ─▶ (3) WPAD ─▶ (4) EFSRPC ─▶ (5) DCSync ─▶ (6) Bronze Bit
   ATTACKER ──FTP / LDAP / NTLM / Kerberos / MSRPC──▶ PALO ALTO NGFW (EAL) ──▶ Cortex XSIAM/XDR
```

| # | Stage (ATT&CK tactic) | What the script does | Enabled EAL alert | Rule id | Technique |
|---|----------------------|----------------------|-------------------|---------|-----------|
| 1 | **INITIAL ACCESS** (TA0001) | Brute-forces an exposed FTP service | **Multiple Suspicious FTP Login Attempts** | `91db0f65` | T1110 · T1078 |
| 2 | **Discovery** (TA0007) | Rare combination of AD/LDAP queries | **Rare LDAP enumeration** | `fcb12ef3` | T1087 |
| 3 | **Credential Access** (TA0006) | Repeated WPAD resolves + `wpad.dat` fetches | **Uncommon WPAD queries** | `f1546fee` | T1557 |
| 4 | **Credential Access** (TA0006) | EFSRPC named-pipe coercion to the DC (PetitPotam) | **Suspicious EFSRPC to domain controller** | `82a37634` | T1550.002 |
| 5 | **Credential Access** (TA0006) | Directory-replication RPC to the DC from a non-DC | **Possible DCSync from a non domain controller** | `b00baad9` | T1003.006 |
| 6 | **Credential Access** (TA0006) | Kerberos S4U / delegation ticket requests | **Bronze-Bit exploit** | `115c6f43` | T1204 |

---

## 2. Prerequisites

| Component | Requirement |
|-----------|-------------|
| Attacker host | Windows, PowerShell 5.1+, domain-joined. |
| Targets | An exposed FTP service (IA), the DC (LDAP/SMB/Kerberos). |
| NGFW / Cortex | EAL enabled + log forwarding; **ITDR / Identity Analytics** enabled. |
| Tools (optional) | Exact EFSRPC/DCSync/Bronze-Bit need `PetitPotam.exe` / `mimikatz` / `Rubeus` in `scripts\tools\` — the native stages generate the traffic and note the tool. |

---

## 3. Run it

**Double-click `Start-Demo.cmd`** → **[1] Configure** → **[2] Preflight → [3] Dry
run → [4] Run**. Failed logins/coercions are the point — scripts warn and
continue; the failed-auth / RPC traffic is what the firewall logs.

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 | Multiple Suspicious FTP Login Attempts | `91db0f65` | many FTP logins in a short window |
| 2 | Rare LDAP enumeration | `fcb12ef3` | unusual LDAP query combination to the DC |
| 3 | Uncommon WPAD queries | `f1546fee` | repeated WPAD lookups from the host |
| 4 | Suspicious EFSRPC to domain controller | `82a37634` | EFSRPC/MSRPC to the DC |
| 5 | Possible DCSync from a non domain controller | `b00baad9` | replication RPC to the DC from a non-DC |
| 6 | Bronze-Bit exploit | `115c6f43` | forwardable Kerberos ticket for a Protected User |

See `docs/verification-checklist.md`.

---

## 5. Safety
Failed logins, WPAD lookups, named-pipe/replication RPC, and normal ticket
requests only. EFSRPC/DCSync/Bronze-Bit are best-effort natively and flag the
tool required for the exact exploit. Authorized labs only. `DryRun` sends nothing.
