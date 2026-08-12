# EAL Demo Repository

This repository contains Palo Alto Networks Enhanced Application Logging (EAL) demo assets for detection-engineering and SE enablement scenarios.

The current demo lives in `case-1/` and simulates a safe, lab-only intrusion flow that generates firewall-observable traffic patterns for Cortex XSIAM / XDR analytics validation.

## Contents

- `case-1/` — AD intrusion to exfiltration demo driven by Windows PowerShell scripts.
- `case-1/README.md` — detailed case documentation, attack-flow diagram, prerequisites, and expected alerts.
- `case-1/Start-Demo.cmd` — double-click launcher that self-elevates and opens the guided menu.
- `case-1/Start-Demo.ps1` — guided PowerShell menu for configuration, preflight checks, dry runs, and execution.
- `case-1/config/lab-config.ps1` — default lab configuration.
- `case-1/scripts/` — stage scripts and the `Run-All.ps1` orchestrator.
- `case-1/docs/verification-checklist.md` — Cortex alert validation checklist.

## Quick start

From a Windows host in an authorized lab:

1. Open `case-1/`.
2. Right-click `Start-Demo.cmd`.
3. Select **Run as administrator**.
4. Use the menu to:
   - configure lab settings,
   - run preflight checks,
   - perform a dry run,
   - execute the full chain or selected stages.

Manual PowerShell entry point:

```powershell
cd .\case-1
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\scripts\Run-All.ps1 -DryRun
```

Run the full guided chain:

```powershell
.\scripts\Run-All.ps1 -PauseBetween
```

## Safety and scope

This repository is intended for authorized lab and demo use only.

The scripts are designed to generate detection telemetry, not to perform real exploitation. They use dummy payloads, safe traffic patterns, and cleanup logic so the scenario can be used for Cortex analytics demonstrations and validation exercises.

Use `-DryRun` before sending traffic in any lab environment.

## Validation

After running the demo, use:

- `case-1/docs/verification-checklist.md` for alert-by-alert validation.
- `case-1/README.md` for expected Cortex XSIAM / XDR alert names, severities, and MITRE ATT&CK mappings.

Analytics detections may take several minutes to appear, depending on Cortex ingestion and detector schedules.

## Repository status

This repository is initialized with Git and is intended to track demo cases, scripts, configuration templates, and validation documentation.
