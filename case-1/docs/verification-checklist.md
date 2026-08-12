# Verification checklist — Case 1 (firewall detect & block)

Run `Run-All.ps1` (or `Start-Demo.cmd` → [4]), then confirm each **firewall**
threat/URL log appears in Cortex XSIAM/XDR. Firewall logs are near real-time.

## Firewall-sourced alerts to confirm

| ✓ | Stage | Firewall alert (search in Cortex / NGFW Monitor) | Action | ATT&CK |
|---|-------|--------------------------------------------------|--------|--------|
| ☐ | 1 | URL Filtering — **phishing** | block | T1566 |
| ☐ | 1 | URL Filtering — **malware** | block | T1189 |
| ☐ | 1 | Antivirus — virus *(only if EICAR enabled)* | reset-both | T1204 |
| ☐ | 2 | URL Filtering — **command-and-control** | block | T1071 |
| ☐ | 2 | DNS Security — `test-c2.testpanw.com` | **sinkhole** | T1071 |
| ☐ | 3 | DNS Security — `test-dga` (DGA) | sinkhole/alert | T1568.002 |
| ☐ | 3 | DNS Security — `test-dnstun` (DNS tunneling) | sinkhole/alert | T1071.004 |
| ☐ | 3 | DNS Security — `test-ddns` / `test-fastflux` | alert | T1568 |
| ☐ | 4 | DNS Security — `test-malware` / `test-ransomware` | sinkhole | T1105/T1486 |
| ☐ | 4 | DNS Security — `test-nrd` (newly-registered) | alert | T1608 |
| ☐ | 4 | URL Filtering — **high-risk** | alert/block | T1608 |
| ☐ | 5 | DNS Security — `test-dns-infiltration` | sinkhole | T1048 |
| ☐ | 5 | DNS Security — `test-proxy` (anonymizer) | alert/block | T1048 |

## Two-place proof (firewall, not agent)

1. **On the NGFW:** *Monitor ▸ Logs ▸ Threat* and *URL Filtering* — the events
   above appear with `action = sinkhole / block / reset`. This is the firewall's
   own record.
2. **In Cortex:** the corresponding alerts list **Palo Alto Networks NGFW** as
   the source (not an endpoint/agent story). XQL:
   ```
   dataset = panw_ngfw_threat_raw
   | filter action in ("sinkhole","block-url","reset-both","drop")
   | fields _time, misc, category, action, src_ip, dst_ip
   | sort desc _time
   ```

## If a firewall alert does NOT appear

1. **Path** — confirm the host's DNS + HTTP actually traverse the PAN firewall
   (not a local resolver / direct egress). Run `00-preflight.ps1`.
2. **Profiles attached** — the security rule for the host must have Anti-Spyware
   (DNS Security), URL Filtering and Antivirus profiles attached, with the
   actions from README §4.
3. **Subscriptions** — DNS Security and Advanced URL Filtering must be licensed
   and active, or the test domains/pages won't be categorized.
4. **HTTP vs HTTPS** — URL test pages must be fetched over `http://` unless SSL
   decryption is enabled (config uses http by default).
5. **Log forwarding** — a Log Forwarding profile must send Threat/URL logs to
   Cortex and be attached to the rule; check the NGFW logs first to isolate
   "firewall didn't act" vs "didn't reach Cortex".
6. **Sinkhole label** — the script prints `[BLOCK]` only when the answer matches
   the default sinkhole IP (72.5.65.x). A custom sinkhole IP still generates the
   firewall log — verify in Monitor ▸ Logs ▸ Threat.

## Demo talk-track

1. Land on a phishing/malware page → **URL Filtering blocks** (stage 1).
2. Implant beacons → **URL C2 block + DNS C2 sinkhole** (stage 2).
3. Malware rotates domains / tunnels DNS → **DNS Security sinkholes** (stage 3).
4. Second-stage/ransomware pull → **DNS + URL blocks** (stage 4).
5. Exfil over DNS / anonymizer → **DNS Security sinkholes** (stage 5).
6. Open the NGFW Threat log + the XSIAM incident → one firewall-caught kill chain.
