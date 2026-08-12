# Verification checklist — Case 6 (Ghost in the DNS)

| ✓ | Stage | Alert (rule id) | Confirm |
|---|-------|-----------------|---------|
| ☐ | 1 (IA) | Phishing site access + malware URL *(URL Filtering)* | victim → phishing/malware URL |
| ☐ | 2 | Subdomain Fuzzing (`fdcaa14c`) | many subdomains of one root from the victim |
| ☐ | 3 | Recurring rare domain access to dynamic DNS domain (`00977673`) | repeated dyn-DNS lookups/beacons |
| ☐ | 4 | Abnormal rare combination of TLS and HTTP User Agent (`7f213d7d`) | odd UA over TLS to the attacker |
| ☐ | 5 | Recurring access to rare domain (`8c2e83de`) + Abnormal Recurring Comms (`c2dbeac4`) | periodic beacons to the rare domain |

## Notes
- Stages 3 & 5 are **multi-day "recurring"** detectors — one run seeds the
  baseline; re-run over several days for the full signal.
- All victim → attacker/DNS traffic must egress via the PAN NGFW (EAL + forwarding).
