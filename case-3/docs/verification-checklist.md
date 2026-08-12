# Verification checklist — Case 3 (web foothold → lateral movement)

Run `Run-All.ps1` (or `Start-Demo.cmd` → [4]), then confirm each enabled EAL rule.
Behavioural analytics take ~10–60 min.

| ✓ | Stage | Alert (rule id) | Confirm |
|---|-------|-----------------|---------|
| ☐ | 1 (IA) | Suspicious HTTP parameters detected (`3508f6b4`) | web-shell params to the web server |
| ☐ | 2 | Abnormal RPC traffic to multiple hosts (`77034682`) | source → many hosts on 135 |
| ☐ | 3 | Abnormal sensitive RPC traffic to multiple hosts (`1820b60e`) | WMI/SCM RPC to many hosts |
| ☐ | 4 | Rare DCOM RPC activity (`9c37ef68`) | DCOM activation to the target |
| ☐ | 5 | Rare WinRM HTTP Activity (`927b7285`) | WinRM 5985 to the target |
| ☐ | 6 | Rare SVCCTL RPC (`a7825b28`) + Rare Scheduled Task RPC (`fc8b21f4`) | remote service + task on target |

## If an alert does not appear
1. HTTP + RPC/WinRM traffic must traverse the PAN firewall.
2. EAL enabled + log forwarding; some detectors need XTH.
3. **Agent shadowing:** with the XDR agent on the source host, lateral alerts may
   show as endpoint/"XDR Analytics" with a process name — run from a non-agent
   host for firewall attribution (see ../case-1/README.md).
4. Baseline "rarity" — DCOM/WinRM to a host never contacted before triggers more
   reliably; re-run from a fresh source host.
