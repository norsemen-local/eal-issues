# Verification checklist — Case 1

Use this after running `Run-All.ps1` to confirm each EAL-log analytics alert
fired in Cortex XSIAM / XDR. Detectors are behavioural and may take ~10–60 min.

## Alert-by-alert

| ✓ | Stage | Alert name (search in Cortex) | Sev | ATT&CK | How to confirm |
|---|-------|-------------------------------|-----|--------|----------------|
| ☐ | 1 | Random-Looking Domain Names | Medium | T1568.002 | Alert lists many random root domains from the attacker host |
| ☐ | 1 | DNS Tunneling | Low | T1071 / T1048 | Parent domain = `tunnel.<DgaRootDomain>`, >10 KB in 10 min |
| ☐ | 2 | Rare LDAP enumeration | Low | T1087 | LDAP/389 attacker → DC, unusual query combination |
| ☐ | 3 | Weakly-Encrypted Kerberos TGT Response | Info | T1556.001 | RC4 / etype 23 Kerberos ticket toward the DC |
| ☐ | 3 | Rare NTLM Usage by User | Info | T1550 | Lab user's first NTLM auth in 30 days, target by IP |
| ☐ | 4 | Rare Scheduled Task RPC activity | Info | T1021 / T1053 | ATTACKER → lateral target, scheduled-task RPC |
| ☐ | 4 | Rare Remote Service (SVCCTL) RPC activity | Info | T1021 | ATTACKER → lateral target, SCM RPC |
| ☐ | 5 | Massive upload to a rare storage or mail domain | Info | T1567.002 | Large outbound transfer to the rare storage domain |

## If an alert does NOT appear

1. **Timing** — most analytics run on a schedule; wait up to an hour. DNS
   Tunneling evaluates a 10-minute window; re-run stage 1 if needed.
2. **Data source** — in Cortex, confirm the **PAN Firewall EAL** source is
   ingesting (Settings ▸ Data Sources). Check the raw logs contain the traffic
   (XQL: `dataset = panw_ngfw_traffic_raw` / DNS / threat as applicable).
3. **Analytics/ITDR enabled** — Kerberos & NTLM detectors need the **ITDR /
   Identity Analytics** module active.
4. **Baseline "rarity"** — these detectors fire on *anomalies*. In a brand-new
   tenant with no baseline, or a very noisy one, sensitivity differs. Re-running
   from a host that has never done this activity helps.
5. **EAL enabled on the NGFW** — Enhanced Application Logging must be on and the
   log-forwarding profile attached to the rules covering the lab segments.
6. **Firewall actually in path** — verify the attacker→DC and attacker→internet
   traffic traverses the PAN firewall (not a direct L2 path).

## Demo talk-track (suggested)

1. Land the implant → **C2 alerts** (DGA + tunnel) prove egress detection.
2. Show **LDAP recon** → attacker is mapping AD.
3. Show **Kerberoast + NTLM** → credential theft without touching the endpoint.
4. Show **RPC lateral movement** → spread to a second host.
5. Show **massive upload** → data leaving the org.
6. Open the **incident/causality view** → one stitched story, MITRE-mapped.
