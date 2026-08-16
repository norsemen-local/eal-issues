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

## The XDR endpoint layer (the other half of the story)

| Stage | Endpoint action | XDR analytic |
|-------|-----------------|-------------|
| 2 | read/export certificate stores | *Suspicious process accessed certificate files* (T1552.004) |

**Story:** credential tooling first raids the certificate stores on the host
(endpoint) — the prelude to the Golden SAML cert theft — then abuses NTLM,
downgrades Kerberos, and reaches ADFS (network/identity).

---

## Detection model
The NTLM/Kerberos/ADFS EAL analytics are **ITDR + baseline** detectors (and need
an AD lab) — they won't fire on a fresh run. So each stage also resolves a
category-matched **DNS-Security test domain** (`test-c2`, `test-malware`,
`test-dns-infiltration` `.testpanw.com`), representing the attacker's tooling
beaconing/exfiltrating during that step → an **instant, firewall-sourced PAN
NGFW** detection with no baseline. The identity alerts in the table are the
"matures over time (+ITDR)" bonus layer.

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

## 4. Real vs simulated — will the FW / XDR agent actually recognise this?

**Legend** — ✅ **REAL·instant (FW)**: signature/category, fires first-run. 🟡
**REAL·baseline (EAL/ITDR)**: genuine traffic the analytic models, fires only with
**ITDR + a real AD/ADFS lab + a matured baseline**. 🔵 **REAL·endpoint (XDR agent
BIOC)**: real host action the agent observes. 🟠 **SIMULATED**: approximation only.

This is an **identity** case: the auth traffic is genuinely emitted, but nothing
authenticates unless you point config at a **live DC/ADFS** — and two of the signals
can't be produced natively at all.

| # | Stage | What the code ACTUALLY sends | Detection | Class | Source |
|---|-------|------------------------------|-----------|-------|--------|
| 1 | Phishing / drive-by IA | Real GETs to PANW URL-Filtering test pages + attacker-IP fetch | Phishing/malware URL categorisation | ✅ **REAL·instant** | FW (URL Filtering) |
| 2e | Cert-store access (endpoint) | **Real** enumerate + `.Export()` of `Cert:\CurrentUser\My` and SystemCertificates files | Suspicious process accessed certificate files (T1552.004) | 🔵 **REAL·endpoint** | XDR agent (BIOC) |
| 2 | Long-user + rare NTLM | **Real** `net use \\IP\IPC$ /user:"<80+ char special name>"` + NTLM-by-IP **+** `test-c2`.testpanw.com | Long-Username Login (T1190) + Rare NTLM (T1550) (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (+ ✅ anchor) | FW (EAL/ITDR) |
| 3 | Machine-account NTLM | `net use \\IP\IPC$` as current user — **only a `$` machine account if launched via `PsExec -s`** **+** `test-malware`.testpanw.com | Machine-account NTLM (T1187) (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (needs SYSTEM ctx) (+ ✅ anchor) | FW (EAL/ITDR) |
| 4 | Weak RC4 Kerberos TGT | Real `KerberosRequestorSecurityToken` TGS requests for 5 SPNs — **etype is NOT forced to RC4** **+** `test-c2`.testpanw.com | Weakly-Encrypted Kerberos TGT (T1556.001) (+ ✅ DNS-Sec) | 🟠 **SIMULATED** (RC4 not guaranteed on AES-default AD) (+ ✅ anchor) | FW (EAL/ITDR) |
| 5 | ADFS sync / Golden SAML | Real `GET /adfs/services/policystoretransfer` + `FederationMetadata.xml`, port probes — **recon connections only; no token-signing-key theft, no SAML forgery** **+** `test-dns-infiltration` / `test-c2`.testpanw.com | Unusual ADFS Remote Sync (T1606.002) (+ ✅ DNS-Sec) | 🟠 **SIMULATED** for the forgery / 🟡 for the recon connections (+ ✅ anchor) | FW (EAL/ITDR) |

**Bottom line:** on a fresh tenant the only guaranteed alerts are stage 1's
phishing hit, the per-stage `test-*.testpanw.com` DNS-Security sinkholes, and (with
an agent) the stage-2 cert-store BIOC. Everything named-identity (stages 2–5)
requires **ITDR/Identity Analytics enabled, a real AD/ADFS lab answering the
traffic, and a matured baseline** — the placeholder targets (`10.0.0.20`,
`DC01.corp.local`, `adfs.corp.local`) won't authenticate in a bare demo. **Two
signals are simulated:** the **RC4 downgrade** (etype not forced — the exact
weak-TGT rule may not fire against modern AES-default AD without RC4-only SPNs or
Rubeus) and the **Golden SAML forgery** (never performed — it requires stealing the
ADFS token-signing key, which no code attempts). Stage 3's machine-account (`$`)
signal only appears when run as **SYSTEM** (`PsExec -s`).

---

## 5. Safety
Failed logins, first-time NTLM, normal (RC4) ticket requests, and ADFS endpoint
connections only — no credential theft. `DryRun` sends nothing. Stage 3 needs
SYSTEM context for the exact machine-account signal. Authorized labs only.
