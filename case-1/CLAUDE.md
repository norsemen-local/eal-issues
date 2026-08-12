# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Case 1 of a 5-case Palo Alto **EAL-log detection demo** (see `../README-cases.md`).
Theme: **Drive-by to Data Theft** — a full malware intrusion. Stage→enabled-rule
chain (source of truth = `README.md` §1):
1. **Initial Access** — Spring4Shell web exploit (`1028c23d`)
2. C2 — Random-Looking Domain Names / DGA flood (`ce6ae037`)
3. C2 — DNS Tunneling >10 KB (`61a5263c`)
4. C2 — Suspicious DNS traffic (`2a77fad6`) + Failed DNS (`74c65024`)
5. Exfil — Abnormal Communication to a Rare Domain (`c2da63d1`)

Every stage maps to an **enabled** analytics rule, and stage 1 is a reliable,
pattern-based Initial Access (don't replace it with a behavioural detector).
Stages 2/3/5 also query PANW DNS-Security test domains (`*.testpanw.com`) so the
firewall additionally **sinkholes/blocks** — the detect-AND-block bonus layer.
Generators live in `scripts/_traffic.ps1` (DGA, tunnel, suspicious/rare DNS,
test-domain blocks); the web IA uses the shared `scripts/_ia.ps1`.

The older AD behavioural stages live under `scripts/optional-ad-eal/` (optional;
agent-shadowed — not part of the main chain).

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
