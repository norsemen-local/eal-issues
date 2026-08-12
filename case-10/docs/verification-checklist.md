# Verification checklist — Case 10 (Tunnels & Shadows)

| ✓ | Stage | Alert (rule id) | Confirm |
|---|-------|-----------------|---------|
| ☐ | 1 (IA) | Phishing site access + malware URL *(URL Filtering)* | victim → phishing/malware URL |
| ☐ | 2 | Uncommon SSH session was established (`18f84dd7`) | SSH to a non-standard port on the attacker |
| ☐ | 3 | Unusual SSH Activity (`f1545c54`) | long, high-volume SSH tunnel |
| ☐ | 4 | Rare access to known advertising domains *(enable if off)* | many connections to obscure ad domains |
| ☐ | 5 | Rare Scheduled Task RPC activity from a rarely seen host *(enable if off)* | remote task created via RPC |

## Notes
- Stages 2–3 use enabled SSH detectors; **enable** the ad-domain (stage 4) and
  rarely-seen-host scheduled-task (stage 5) detectors if the alerts don't appear.
- Stage 3's "high volume/long session" is approximated (a few hundred KB + a short
  hold); a real tunnel over time strengthens the signal.
- Stage 5 needs admin on the remote host; failures still generate the RPC traffic.
