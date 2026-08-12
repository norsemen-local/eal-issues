# Case 1 — Drive-by to Data Theft (Malware C2 & Exfil)

**Lifecycle:** a Windows **victim** is phished/drive-by compromised, the implant
beacons out to the **attacker** (Kali) over DGA domains and DNS tunneling, makes
suspicious/failed DNS lookups, and exfiltrates to a rarely-seen domain. The Palo
Alto NGFW logs it as **EAL logs**; Cortex XSIAM/XDR raises the analytics alerts;
and DNS Security **sinkholes/blocks** the test domains woven in (detect **and**
block).

- **Roles:** Kali = attacker / C2 (`AttackerC2`, default `170.187.158.212`);
  this Windows host = victim (runs the scripts). All traffic is victim → attacker.
- One of five cases — see [`../README.md`](../README.md) and
  [`../README-cases.md`](../README-cases.md).

---

## 1. Attack flow → enabled EAL rules

```
  VICTIM(Windows) ──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR       ATTACKER(Kali)=C2
   (1) PHISHING/DRIVE-BY ─▶ (2) DGA ─▶ (3) DNS tunnel ─▶ (4) odd DNS ─▶ (5) rare-domain exfil
```

| # | Stage (ATT&CK tactic) | What the victim does | Enabled EAL / firewall alert | Rule id | Technique |
|---|----------------------|----------------------|------------------------------|---------|-----------|
| 1 | **INITIAL ACCESS** (TA0001) | Lured to a phishing page + malware drive-by, pulls payload from the attacker | **Phishing site access** / **Suspicious Phishing Site Access** + malware URL (URL Filtering) | *(URL Filtering)* | T1566 · T1204 |
| 2 | **C2** (TA0011) | 45 random-looking domain lookups (DGA) | **Random-Looking Domain Names** | `ce6ae037` | T1568.002 |
| 3 | **C2 / Exfil** (TA0011) | >10 KB encoded into DNS subdomains | **DNS Tunneling** | `61a5263c` | T1071.004 |
| 4 | **C2** (TA0011) | Malformed / non-existent DNS lookups | **Suspicious DNS traffic** + **Failed DNS** | `2a77fad6`, `74c65024` | T1071.004 |
| 5 | **EXFILTRATION** (TA0010) | Repeated comms to a rarely-seen domain | **Abnormal Communication to a Rare Domain** | `c2da63d1` | T1567 |

**Firewall block layer (bonus):** stages 2/3/5 also query PANW DNS-Security test
domains (`test-dga`, `test-dnstun`, `test-dns-infiltration` `.testpanw.com`) so
the firewall **sinkholes/blocks** them — visible in Monitor ▸ Logs ▸ Threat.

---

## 2. Prerequisites
- Windows victim, PowerShell 5.1+, egress **through the PAN NGFW** (EAL + log
  forwarding to Cortex; DNS Security for the block layer).
- The Kali attacker box up (`attacker/attacker-setup.sh`) so the phishing-page /
  payload pull resolves. The "Phishing site access" alert itself comes from the
  URL-Filtering test pages and needs only firewall egress.

---

## 3. Run it

Via the global orchestrator (recommended):
```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 1 -DryRun     # rehearse
.\Invoke-AttackLifecycle.ps1 -Cases 1 -Live       # run
```
Or standalone: **`case-1\Start-Demo.cmd`** → **[2] Preflight → [3] Dry run →
[4] Run**. Set the attacker/C2 host via **[1] Configure** (`AttackerC2`).

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 | Phishing site access + malware URL | *(URL Filtering)* | victim → phishing/malware URL + attacker host |
| 2 | Random-Looking Domain Names | `ce6ae037` | many random root domains from the victim |
| 3 | DNS Tunneling | `61a5263c` | >10 KB under `tunnel.<DgaRootDomain>` |
| 4 | Suspicious DNS traffic / Failed DNS | `2a77fad6` / `74c65024` | malformed / NXDOMAIN lookups |
| 5 | Abnormal Communication to a Rare Domain | `c2da63d1` | recurring hits to the rare domain |

Firewall block proof: **Monitor ▸ Logs ▸ Threat** shows the `test-*.testpanw.com`
DNS Security sinkholes. See [`docs/verification-checklist.md`](docs/verification-checklist.md).

---

## 5. Safety
Phishing uses Palo Alto's benign URL-Filtering test pages; DNS lookups are benign;
PANW test domains only. `DryRun` sends nothing. Authorized labs only.
