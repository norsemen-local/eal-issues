# Verification checklist — Case 5 (covert channels & exfil)

Run `Run-All.ps1` (or `Start-Demo.cmd` → [4]), then confirm each enabled EAL rule.
Analytics take ~10–60 min.

| ✓ | Stage | Alert (rule id) | Confirm |
|---|-------|-----------------|---------|
| ☐ | 1 (IA) | FTP Connection Using an Anonymous Login or Default Credentials (`68d806a3`) | anonymous/default FTP login |
| ☐ | 2 | Multiple Suspicious FTP Login Attempts (`91db0f65`) | many FTP logins, short window |
| ☐ | 3 | Multiple uncommon SSH Servers with the same Server host key (`f154d651`) | SSH to several servers sharing a key |
| ☐ | 4 | Suspicious SSH Downgrade (`f154f3c5`) | legacy SSH-1.5/1.99 client version |
| ☐ | 5 | Suspicious ICMP packet (`f3389ebd`) + echo-to-multiple (`09f9a9a7`) + smurf (`72694178`) | oversized / multi-host / broadcast ICMP |
| ☐ | 6 | Rare file transfer over SMB protocol (`045e06dd`) | large copy to a rarely-used SMB share |

## If an alert does not appear
1. FTP/SSH/ICMP/SMB traffic must traverse the PAN firewall (not a bypass path).
2. EAL enabled + log forwarding to Cortex.
3. **Stage 3** requires 2+ SSH servers that actually **share a host key** — a
   property of the targets; clone a VM or reuse a key to trigger it.
4. **Stage 5** — the exact "Suspicious ICMP packet" detector wants a router
   advertisement (raw socket / tool); native ping generates the tunnel /
   multi-host / broadcast patterns the firewall logs.
5. **Stage 6** — the SMB share must be reachable through the firewall; a denied
   write still creates the logged SMB session.
