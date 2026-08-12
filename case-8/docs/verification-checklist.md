# Verification checklist — Case 8 (The Departing Employee)

| ✓ | Stage | Alert (rule id) | Confirm |
|---|-------|-----------------|---------|
| ☐ | 1 | Increase in Job-Related Site Visits + multiple time-consuming websites *(enable if off)* | many job-board + streaming visits |
| ☐ | 2 | New FTP Server (`ce208ea2`) + A rare FTP user (`df8fa99b`) | first-seen FTP server, unusual user |
| ☐ | 3 | Massive upload to a rare storage or mail domain *(enable if off)* | large outbound to rare storage/mail |

## Notes
- Stage 2 rules are enabled in the tenant; stages 1 & 3 use behavioural
  insider/exfil detectors — **enable them in Cortex** if the alerts don't appear.
- Stage 1 uses real job/streaming sites — the firewall's URL-Filtering categories
  (job-search / streaming-media) feed the analytics.
- Stage 3's exact detector wants an online-storage/webmail-categorised destination;
  point `StorageDomain` at such a host for the precise alert.
