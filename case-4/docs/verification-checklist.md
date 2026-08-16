# Verification checklist — Case 4 (identity & AD domination)

Run `Run-All.ps1` (or `Start-Demo.cmd` → [4]), then confirm each enabled EAL rule.
Needs **ITDR / Identity Analytics** enabled. Analytics take ~10–60 min.

| ✓ | Stage | Alert (rule id) | Confirm |
|---|-------|-----------------|---------|
| ☐ | 1 (IA) | Phishing site access + malware URL (URL Filtering) | victim → phishing/malware test URL + attacker host |
| ☐ | 2 | Rare LDAP enumeration (`fcb12ef3`) | unusual LDAP query combo to the DC |
| ☐ | 3 | Uncommon WPAD queries (`f1546fee`) | repeated WPAD resolves/fetches |
| ☐ | 4 | Suspicious EFSRPC to domain controller (`82a37634`) | EFSRPC/MSRPC to the DC |
| ☐ | 5 | Possible DCSync from a non domain controller (`b00baad9`) | replication RPC from a non-DC |
| ☐ | 6 | Bronze-Bit exploit (`115c6f43`) | forwardable ticket for a Protected User |

## If an alert does not appear
1. **ITDR / Identity Analytics** must be enabled — stages 3–6 depend on it.
2. Traffic must traverse the PAN firewall with EAL + log forwarding.
3. **Stage 4/5/6** need helper tools for the exact exploit. Run with
   **`-EnableRealExploits`** AND drop the matching operator-supplied tool in
   `scripts\tools\` — with both present the stage now actually **runs the tool**
   (was: traffic-only). Without the flag, or with no tool, the stages stay
   traffic-only and only generate the coercion/replication/Kerberos traffic.
   - EFSRPC → `PetitPotam.exe` / `Coercer.exe`
   - DCSync → `mimikatz lsadump::dcsync` / Impacket `secretsdump -just-dc`
   - Bronze Bit → `Rubeus s4u /bronzebit` / Impacket `getST -force-forwardable`
   The DCSync (`secretsdump`) and Bronze-Bit (`getST`) Impacket paths need
   credentials/hashes the operator supplies (the tool prompts); nothing is
   hardcoded. These run real credential operations against the lab DC.
4. Agent shadowing may attribute stages 2–6 to the endpoint (see ../case-1).
