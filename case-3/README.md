# EAL Demo — Case 3: Web Foothold → Windows Lateral Movement

A complete intrusion: the attacker **breaches a public-facing web app and drops a
web shell (Initial Access)**, then pivots across Windows hosts using remote-admin
RPC — an endpoint-mapper sweep, sensitive RPC, DCOM activation, WinRM, and remote
service/scheduled-task execution. The Palo Alto NGFW logs the HTTP + MSRPC/WinRM
traffic as **EAL logs**; Cortex XSIAM/XDR raises the alerts.

> One of five demo cases (see `../README-cases.md`). Every stage maps to an
> **enabled** EAL rule. These lateral-movement detectors are behavioural — with
> an XDR agent on the *source* host some may be attributed to the endpoint (see
> `../case-1/README.md`); run from a non-agent host for clean firewall
> attribution.

---

## 1. Attack flow → enabled EAL rules

```
   (1) WEB SHELL ─▶ (2) RPC sweep ─▶ (3) sensitive RPC ─▶ (4) DCOM ─▶ (5) WinRM ─▶ (6) SVCCTL+SchedTask
   ATTACKER ──HTTP + MSRPC/WinRM──▶ PALO ALTO NGFW (EAL) ──▶ Cortex XSIAM/XDR
```

| # | Stage (ATT&CK tactic) | What the script does | Enabled EAL alert | Rule id | Technique |
|---|----------------------|----------------------|-------------------|---------|-----------|
| 1 | **INITIAL ACCESS** (TA0001) | Web-shell params + Spring4Shell on the public app | **Suspicious HTTP parameters detected** | `3508f6b4` | T1190 · T1505.003 |
| 2 | **Discovery** (TA0043) | Probes RPC endpoint mapper (135) across many hosts | **Abnormal RPC traffic to multiple hosts** | `77034682` | T1595 |
| 3 | **Lateral Movement** (TA0008) | WMI/DCOM + SCM queries across many hosts | **Abnormal sensitive RPC traffic to multiple hosts** | `1820b60e` | T1021 |
| 4 | **Lateral Movement** (TA0008) | Activates DCOM objects on a remote host | **Rare DCOM RPC activity** | `9c37ef68` | T1021.003 |
| 5 | **Lateral Movement** (TA0008) | `Invoke-Command` / `Test-WSMan` over WinRM (5985) | **Rare Windows Remote Management (WinRM) HTTP Activity** | `927b7285` | T1021 |
| 6 | **Lateral Movement** (TA0008) | Remote service (SVCCTL) + scheduled-task RPC | **Rare Remote Service (SVCCTL) RPC activity** + **Rare Scheduled Task RPC activity** | `a7825b28`, `fc8b21f4` | T1021 · T1053 |

---

## 2. Prerequisites

| Component | Requirement |
|-----------|-------------|
| Attacker host | Windows, PowerShell 5.1+, **elevated** (helps DCOM/WMI/SCM). Prefer a **non-agent** host for clean FW attribution. |
| Web server (IA) | A lab web server reachable through the firewall (`TargetWebServer`, http://). |
| Targets | Several reachable Windows hosts (`SweepHosts`); a member server for DCOM/WinRM/SchedTask (`LateralTarget`); lab account admin on targets. |
| NGFW / Cortex | EAL enabled + log forwarding; Analytics (and XTH where noted) enabled. |

---

## 3. Run it

**Double-click `Start-Demo.cmd`** → **[1] Configure** → **[2] Preflight → [3] Dry
run → [4] Run**. Or `.\scripts\Run-All.ps1 -PauseBetween`. Failed remote calls
(no admin, host down) are expected and still generate the RPC/WinRM traffic.

---

## 4. Expected in Cortex XSIAM / XDR

| Stage | Alert | Rule id | Confirm |
|-------|-------|---------|---------|
| 1 | Suspicious HTTP parameters detected | `3508f6b4` | web-shell params to the web server |
| 2 | Abnormal RPC traffic to multiple hosts | `77034682` | source → many hosts on 135 |
| 3 | Abnormal sensitive RPC traffic to multiple hosts | `1820b60e` | WMI/SCM RPC to many hosts |
| 4 | Rare DCOM RPC activity | `9c37ef68` | DCOM activation to the target |
| 5 | Rare WinRM HTTP Activity | `927b7285` | WinRM 5985 to the target |
| 6 | Rare SVCCTL RPC + Rare Scheduled Task RPC | `a7825b28`, `fc8b21f4` | remote service + task on the target |

Cortex should stitch these into one lateral-movement incident. See
`docs/verification-checklist.md`.

---

## 5. Safety
Dummy web-shell pattern; remote object/service/task calls create-and-delete;
failures swallowed. Authorized labs only. `DryRun` sends nothing.
