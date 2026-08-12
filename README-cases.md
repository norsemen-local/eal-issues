# PANW EAL Demo — Five Full-Chain Use Cases

Five independent demo cases. **Each shows the complete attack flow starting with
a clear, reliably-triggered Initial Access**, and **every stage maps to an EAL
analytics rule that is ENABLED in the tenant** (rule IDs below). All run on
Windows/PowerShell via a one-click `Start-Demo.cmd`.

Alert reference:
<https://cortex-docs.paloaltonetworks.com/analytics-alerts/alerts-by-data-source/palo-alto-networks-firewall-eal-logs>

---

## Initial Access — how each case shows "the attacker got in"

Only a few EAL rules are genuine, pattern-based (reliable) **Initial Access**
detectors. Each case opens with one of them, so the entry point is never
ambiguous:

| Case | Initial Access stage | Enabled rule | Rule id |
|------|----------------------|--------------|---------|
| 1 | Web exploit (Spring4Shell) on public app | Suspicious failed HTTP request - Spring4Shell | `1028c23d` |
| 2 | Web recon → exploit (path traversal + Spring4Shell) | Possible path traversal / Spring4Shell | `60da6e16` / `1028c23d` |
| 3 | Web-shell drop on public app | Suspicious HTTP parameters detected | `3508f6b4` |
| 4 | Brute-force exposed FTP | Multiple Suspicious FTP Login Attempts | `91db0f65` |
| 5 | Anonymous/default FTP login | FTP Connection Using Anonymous/Default Credentials | `68d806a3` |

---

## The five cases (stage → enabled rule)

### Case 1 — Drive-by to Data Theft (Malware C2 & Exfil)
1. **IA** Spring4Shell `1028c23d` → 2. Random-Looking Domain Names `ce6ae037`
→ 3. DNS Tunneling `61a5263c` → 4. Suspicious DNS traffic `2a77fad6` + Failed DNS
`74c65024` → 5. Abnormal Communication to a Rare Domain `c2da63d1`
*(+ firewall DNS-Security sinkhole/block layer)*

### Case 2 — Public-Facing Web-App Exploitation
1. Path traversal `60da6e16` → 2. **IA** Spring4Shell `1028c23d` → 3. Suspicious
HTTP parameters `3508f6b4` → 4. Rare HTTP UA+Server `c13fd72e` → 5. HTTP with
suspicious characteristics `7fbfd969`

### Case 3 — Web Foothold → Windows Lateral Movement
1. **IA** web shell `3508f6b4` → 2. Abnormal RPC to multiple hosts `77034682`
→ 3. Abnormal sensitive RPC `1820b60e` → 4. Rare DCOM RPC `9c37ef68` → 5. Rare
WinRM HTTP `927b7285` → 6. Rare SVCCTL RPC `a7825b28` + Rare Scheduled Task RPC
`fc8b21f4`

### Case 4 — Identity Compromise & AD Domination
1. **IA** FTP brute `91db0f65` → 2. Rare LDAP enumeration `fcb12ef3` → 3. Uncommon
WPAD queries `f1546fee` → 4. Suspicious EFSRPC to DC `82a37634` → 5. Possible
DCSync from non-DC `b00baad9` → 6. Bronze-Bit exploit `115c6f43`

### Case 5 — Covert Channels & Exfiltration
1. **IA** FTP anon/default `68d806a3` → 2. Multiple FTP login attempts `91db0f65`
(+ rare FTP user `df8fa99b`) → 3. Uncommon SSH servers same key `f154d651` (+ SSH
session `18f84dd7`) → 4. SSH downgrade `f154f3c5` (+ Unusual SSH Activity
`f1545c54`) → 5. Suspicious ICMP `f3389ebd` (+ echo-to-multiple `09f9a9a7`, smurf
`72694178`) → 6. Rare SMB file transfer `045e06dd`

> Every rule id above appears in the tenant's enabled-rules list. Collectively
> the five cases exercise ~25 enabled EAL detectors across the full ATT&CK arc.

---

## Common structure (every case)

```
case-N/
├── README.md                  <- design, attack flow, step-by-step, expected alerts + rule ids
├── Start-Demo.cmd             <- DOUBLE-CLICK: self-elevating guided launcher
├── Start-Demo.ps1             <- menu (preflight / dry-run / run / single stage)
├── config/lab-config.ps1      <- targets, DryRun, stage map (_StageMap), rule mapping
├── scripts/
│   ├── 00-preflight.ps1       <- reachability checks
│   ├── 01-initial-access-*    <- the reliable entry point
│   ├── 0N-*.ps1               <- the rest of the chain
│   └── Run-All.ps1            <- orchestrator (stage list from config)
└── docs/verification-checklist.md
```

- **One-click:** `Start-Demo.cmd` → **[2] Preflight → [3] Dry run → [4] Run**.
  `[1] Configure` sets targets without editing files.
- **`-DryRun`** prints every action and sends no traffic.
- **Initial access is pattern-based** (web exploit / FTP) so it fires reliably;
  later behavioural stages depend on tenant baselines and (for identity/RPC) on
  ITDR/Analytics being enabled.
- **Benign:** dummy exploit patterns, PANW test resources, failed logins. No
  malware, no real exploitation. A few exact exploits (EFSRPC, DCSync, Bronze
  Bit, ICMP router-advertisement) note the helper tool needed; the native stages
  still generate the network traffic the firewall logs.

---

## Per-case lab needs

| Case | Needs | Notes |
|------|-------|-------|
| 1 | Web server + DNS egress through NGFW; DNS Security for the block layer | fires reliably; detect **and** block |
| 2 | Web server through NGFW; Vulnerability Protection | web signatures also block |
| 3 | Web server (IA) + several Windows hosts + a member server | behavioural — prefer a non-agent source host |
| 4 | FTP (IA) + DC; **ITDR/Identity Analytics enabled** | EFSRPC/DCSync/Bronze-Bit need helper tools for the exact exploit |
| 5 | FTP + SSH servers + ICMP target + SMB share through NGFW | SSH same-host-key is a target property |

> **Agent-shadowing note:** behavioural EAL analytics (cases 3–4, parts of 5) can
> be attributed to an XDR agent on the source host. Firewall Threat-Prevention
> enforcement (case 1's block layer, case 2's Vuln-Protection) is always
> firewall-sourced. See `case-1/README.md` for the full explanation.
