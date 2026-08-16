# Verification checklist — Case 9 (Pass-the-Hash Playbook)

Needs **ITDR / Identity Analytics** enabled; several rules may need turning on.

| ✓ | Stage | Alert | Technique | Confirm |
|---|-------|-------|-----------|---------|
| ☐ | 1 (IA) | Phishing site access + malware URL | T1566 | victim → phishing/malware URL |
| ☐ | 2 | Failed Login For a Long Username + Rare NTLM Usage by User | T1190 · T1550 | long/odd username, first NTLM in 30d |
| ☐ | 3 | Suspicious NTLM authentication with machine account | T1187 | NTLM by a `*$` machine account |
| ☐ | 4 | Weakly-Encrypted Kerberos TGT Response | T1556.001 | RC4 / etype 23 ticket to the DC |
| ☐ | 5 | Unusual ADFS Remote Synchronization from non-ADFS server | T1606.002 | ADFS sync from a non-ADFS host |

## Notes
- **Enable the identity detectors + ITDR** if the alerts don't appear.
- **Stage 3** needs the machine account → run as SYSTEM (`PsExec -s`); as a normal
  user it still shows NTLM-by-IP under the user account.
- **Stage 4** — native requests generate Kerberos traffic; for a guaranteed RC4
  downgrade, run with **`-EnableRealExploits`** and drop **`Rubeus.exe`** in
  `scripts\tools\` (edit the `<user>`/`<rc4hash>` operator-secret placeholders in
  `04-kerberos-rc4.ps1`). Rubeus `asktgt /rc4` forces the weak etype 23.
- **Stage 5** — recon connections by default; run with **`-EnableRealExploits`**
  plus the **AADInternals** module (or **`ADFSDump.exe`** in `scripts\tools\`) on
  the lab **ADFS server** to perform a real token-signing-key export. Forging the
  SAML token remains a manual operator step.
- **`-EnableRealExploits`** is OFF by default (traffic-only). When set AND the
  matching tool/module is present, the stage shells out to that operator tool;
  otherwise it stays traffic-only. `-DryRun` never executes a tool.
