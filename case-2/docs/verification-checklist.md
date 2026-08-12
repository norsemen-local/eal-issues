# Verification checklist — Case 2 (web-app exploitation)

Run `Run-All.ps1` (or `Start-Demo.cmd` → [4]), then confirm each EAL alert in
Cortex XSIAM/XDR. EAL analytics can take ~10–60 min; Vuln-Protection blocks are
near real-time.

| ✓ | Stage | Alert (search in Cortex) | Sev | ATT&CK | Confirm |
|---|-------|--------------------------|-----|--------|---------|
| ☐ | 1 | Possible path traversal via HTTP request | Low | T1083 | `../` / `%2e%2e` URIs to the web server |
| ☐ | 2 | Suspicious failed HTTP request - potential Spring4Shell exploit | Low | T1190 | `class.module.classLoader` payload |
| ☐ | 3 | Suspicious HTTP parameters detected | Medium | T1133/T1505.003 | `cmd=`, SSTI `{{7*7}}`, `php://filter` |
| ☐ | 4 | Abnormal ... rare combination of HTTP User Agent and HTTP Server | Info/Low | T1102/T1567 | odd User-Agent to external host |
| ☐ | 5 | HTTP with suspicious characteristics | Low | T1102/T1567 | PUT/PATCH + encoded data |

## Firewall-side block proof (stages 1–3)
NGFW **Monitor ▸ Logs ▸ Threat** — Vulnerability Protection signatures for path
traversal / Spring4Shell / code-injection with `action = reset/block`.

## If an alert does not appear
1. Traffic must traverse the PAN firewall to the web server (not a direct path).
2. EAL must be enabled and Vuln-Protection/URL profiles attached to the rule.
3. Use `http://` (config default) unless SSL decryption is enabled.
4. Analytics need a baseline — re-run if the tenant is brand-new.
5. Confirm the firewall saw the requests (Monitor ▸ Logs ▸ URL/Threat) before
   assuming the alert failed vs the log never reached Cortex.
