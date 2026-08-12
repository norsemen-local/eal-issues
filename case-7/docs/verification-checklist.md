# Verification checklist — Case 7 (Poisoned Well)

| ✓ | Stage | Alert (rule id) | Confirm |
|---|-------|-----------------|---------|
| ☐ | 1 (IA) | Phishing site access + malware URL *(URL Filtering)* | victim → phishing/malware URL |
| ☐ | 2 | Rare MS-Update Server was detected (`3d068240`) | update requests to an unexpected server |
| ☐ | 3 | Rare MS-Update traffic over HTTP (`a3602352`) | update download over plain HTTP |
| ☐ | 4 | Unique client computer model via MS-Update protocol (`59b720f1`) | unusual device model on the update protocol |
| ☐ | 5 | Abnormal Communication to a Rare Domain (`c2da63d1`) | trojan beacons to the rare C2 domain |

## Notes
- MS-Update stages need the traffic to app-ID as `ms-update` on the firewall —
  use `http://` (config default) so it's readable without decryption.
- Stage 4's device model is advertised in request metadata (best-effort); the
  native WSUS inventory field can't be fully reproduced without a real update client.
