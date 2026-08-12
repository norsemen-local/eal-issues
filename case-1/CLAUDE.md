# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A **detection-engineering / SE demo**, not a shipping application. It drives a
5-stage MITRE ATT&CK attack chain (initial access → C2 → DGA/DNS-tunneling →
malware/ransomware staging → exfiltration) from a single Windows host so that a
**Palo Alto Networks NGFW itself detects and BLOCKS** the traffic (DNS Security
sinkhole, URL Filtering block, Antivirus reset) and Cortex XSIAM/XDR shows the
resulting **firewall threat/URL logs**.

**Key design decision (do not regress):** the demo is *firewall-enforcement*
centric, not *behavioural-analytics* centric. Firewall Threat-Prevention logs are
unambiguously firewall-sourced and are **not shadowed by the Cortex XDR agent**,
so the demo works even when every lab host runs the agent. See `README.md` §8.
All traffic uses Palo Alto's **official benign test resources** — the
`*.testpanw.com` DNS Security test domains and the
`urlfiltering.paloaltonetworks.com` URL Filtering test pages — never real
malware/C2. The exact FQDNs/categories are the source of truth in `README.md` §1.

The earlier AD behavioural-analytics stages (EAL "Rare LDAP enumeration",
Kerberoast, RPC) live under `scripts/optional-ad-eal/` as an optional add-on;
they get attributed to the endpoint agent and are **not** the primary demo.

## Running

Entry point is **`Start-Demo.cmd`** (double-click) → `Start-Demo.ps1` menu
(preflight / dry-run / run / single-stage / show-expected). The firewall demo
needs **no configuration** — test resources are built into `lab-config.ps1`.
Under the hood it's just the scripts; keep them runnable standalone:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\00-preflight.ps1              # verify DNS/HTTP egress via the firewall
.\scripts\Run-All.ps1 -DryRun           # print every action, send NO traffic
.\scripts\Run-All.ps1 -PauseBetween     # full chain, pause between stages
.\scripts\Run-All.ps1 -Stages 2,3       # any subset
.\scripts\03-dga-dns-tunneling.ps1      # any stage runs standalone
```

There is **no build/lint/test toolchain**. "Testing" a change means: syntax-check
with `[System.Management.Automation.PSParser]::Tokenize(...)`, then run the
affected stage (or `Run-All.ps1`) with `-DryRun`. Live-fire only in a real lab
behind a PAN firewall. Note: `Run-All.ps1`'s `$map` MUST be a plain `@{}`
hashtable (keyed by int), **not** `[ordered]@{}` — an ordered dictionary indexes
by position, which silently shifts stages off-by-one.

## Architecture / conventions to preserve

- **Every stage script has the same shape:** `param([switch]$DryRun)` →
  dot-source `..\config\lab-config.ps1` → dot-source `_traffic.ps1` →
  `if ($DryRun) { $cfg.DryRun = $true }` → call `Invoke-TestUrl` /
  `Invoke-TestDns` / `Invoke-EicarDownload` → end with `Write-Stage "... Expect
  FIREWALL: ..."` lines. New stage → follow this and add it to `$map` in
  `Run-All.ps1` (int key = stage number).
- **`scripts/_traffic.ps1`** holds the only traffic generators. They honour
  `$cfg.DryRun`, treat a firewall **block/sinkhole/failure as success** (log it
  `[BLOCK]`, never throw — the block is the signal), and log `[OK]` when traffic
  was only categorized/alerted. Keep that "failure still counts" behaviour.
- **All configuration is the single `$Global:EalDemo` hashtable** in
  `config/lab-config.ps1` (URL test base, DNS test domain, pacing, `DryRun`,
  EICAR toggle). Scripts read from `$cfg`, never hard-code. `Write-Stage` (shared
  logger, incl. the `BLOCK`/magenta level) is defined here. `lab-config.local.ps1`
  is dot-sourced last for optional overrides.
- **`DryRun` must stay honored on every traffic-emitting path** — it's the
  rehearsal safety mechanism.
- **URL test pages use `http://`** (not https) by default so the firewall can
  read the path without decryption. Don't switch to https without noting the
  decryption requirement.

## When editing stage/alert mappings

`README.md` §1/§6, `docs/verification-checklist.md`, and the `Write-Stage "...
Expect FIREWALL ..."` strings in the scripts must stay in sync — same test
domains/categories, firewall actions (sinkhole/block/alert), and ATT&CK IDs. The
firewall-side config those alerts depend on is documented in `README.md` §4
(profile actions); update it too if you change which category a stage exercises.
`Start-Demo.ps1`'s `Show-Expected` greps README table rows (`^\| \d `), so keep
that table format.
