# Verification checklist — Case 1 (drive-by to data theft)

Run `Run-All.ps1` (or `Start-Demo.cmd` → [4]), then confirm each enabled EAL
rule fired in Cortex XSIAM/XDR. Analytics take ~10–60 min; firewall blocks are
near real-time.

| ✓ | Stage | Alert (rule id) | Confirm |
|---|-------|-----------------|---------|
| ☐ | 1 (IA) | Suspicious failed HTTP request - Spring4Shell (`1028c23d`) | `class.module.classLoader` request to web server |
| ☐ | 2 | Random-Looking Domain Names (`ce6ae037`) | many random root domains from the host |
| ☐ | 3 | DNS Tunneling (`61a5263c`) | >10 KB under `tunnel.<DgaRootDomain>` |
| ☐ | 4 | Suspicious DNS traffic (`2a77fad6`) + Failed DNS (`74c65024`) | malformed / NXDOMAIN lookups |
| ☐ | 5 | Abnormal Communication to a Rare Domain (`c2da63d1`) | recurring hits to the rare domain |
| ☐ | + | Firewall block: DNS Security sinkholes (`test-*.testpanw.com`) | Monitor ▸ Logs ▸ Threat, action=sinkhole |

## If an alert does not appear
1. Traffic must traverse the PAN firewall with EAL + log forwarding to Cortex.
2. Initial-access alert is pattern-based (reliable); the DNS analytics need
   volume — the defaults (45 DGA domains, 15 KB tunnel) are sized to trigger.
3. Rare-domain / suspicious-DNS detectors are baseline-sensitive; run from a host
   that doesn't normally contact those domains.
4. For the firewall block layer, DNS Security must be licensed and enforcing.
