# Attack-Lifecycle mode — one global orchestrator, real intrusions

This is the top-level way to run the demo. Each case is a **complete, role-correct
attack lifecycle**, and a single script provisions the attacker, gets all the
parameters, and runs every case one at a time — unattended.

## Topology (roles)

```
   ┌────────────────────┐        PAN NGFW (EAL + log fwд)        ┌──────────────────┐
   │  KALI  = ATTACKER   │◀──────────────┬──────────────────────▶│  WINDOWS = VICTIM │
   │  / C2 / phishing /   │   victim⇄attacker traffic (all cases) │  (runs the scripts)│
   │  exfil  170.187.158.212                                      │                    │
   └────────────────────┘                                         └─────────┬────────┘
                                                                            │ internal
                                                                   ┌────────▼────────┐
                                                                   │  DC / servers   │  (cases 3-4)
                                                                   └─────────────────┘
```

- **Kali (170.187.158.212)** = the attacker: hosts the phishing page + payload,
  receives C2 beacons and exfil, and (case 2) actively exploits the victim.
- **Windows** = the victim endpoint where the scripts run. Its malicious activity
  is *outbound* to the attacker / internal targets — exactly how a compromised
  host behaves.
- **DC / member servers** = internal targets for the AD stages (cases 3–4),
  auto-detected from the victim's domain membership.

## The five lifecycles

| Case | Lifecycle (Initial Access → … → Objective) | Direction |
|------|--------------------------------------------|-----------|
| **1** | **Phishing/drive-by** → payload from attacker → **DGA C2** → **DNS tunneling** → suspicious/failed DNS → **exfil to rare domain** | victim → attacker |
| **2** | **Attacker exploits the victim's web app** (path traversal → Spring4Shell → web-shell params) | **attacker → victim** |
| **3** | **Phishing** → **RPC recon** → **DCOM / WinRM / SVCCTL / Scheduled-Task** lateral movement | victim → internal |
| **4** | **Phishing** → **LDAP recon** → **WPAD** → **EFSRPC (PetitPotam)** → **DCSync** → **Bronze Bit** | victim → DC |
| **5** | **Phishing** → **FTP** exfil channel → **SSH** (uncommon/downgrade) → **ICMP** covert → **SMB** exfil | victim → attacker |

Every stage maps to an **enabled** EAL rule (rule IDs are in each case's
`README.md` §1 and printed at runtime).

## 0. Passwordless SSH to the attacker (once)

So SSH/scp/provisioning never prompt for the Kali password again, install a key
on the attacker (you enter the password one time; nothing is stored in plaintext):
```powershell
.\Setup-AttackerAuth.ps1                 # root@170.187.158.212 by default
.\Setup-AttackerAuth.ps1 -Attacker 1.2.3.4 -User kali
```
This is the secure alternative to saving a password variable — the credential
lives as an authorized key on the remote machine, not as plaintext on disk.

## 1. Provision the attacker (once)

The orchestrator can push + start the attacker infra for you:
```powershell
.\Invoke-AttackLifecycle.ps1 -Provision -DryRun     # show what it would do
.\Invoke-AttackLifecycle.ps1 -Provision -Live       # actually provision + run
```
It `scp`s `attacker/attacker-setup.sh` + `attacker/attack-web.sh` to Kali and runs
them (HTTP phishing/C2/exfil :80, anon FTP :21, SSH :2201-2203 same key, SMB
share, tools). **SSH auth happens in your session** — approve the 1Password
prompt. (Or run `attacker-setup.sh` on Kali by hand once — see
`README-scenarios.md`.)

> The server's cloud security group must allow inbound 21, 80, 445, 2201–2203.

## 2. Run the lifecycles (from the Windows victim, elevated)

```powershell
cd D:\PANW\eal-demo
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

.\Invoke-AttackLifecycle.ps1 -DryRun                 # rehearse everything, no traffic
.\Invoke-AttackLifecycle.ps1 -Live                   # run all 5 lifecycles, for real
.\Invoke-AttackLifecycle.ps1 -Cases 1,4,5 -Live      # a subset
.\Invoke-AttackLifecycle.ps1 -Provision -Live        # provision Kali, then run all
```

It auto-detects the **victim IP** (as the attacker sees it) and the **AD domain /
DC**, writes each case's `config/lab-config.local.ps1`, and runs the cases
sequentially. Override anything:

| Switch | Purpose |
|--------|---------|
| `-Attacker <ip>` | Kali attacker/C2 (default `170.187.158.212`) |
| `-VictimIP <ip>` | victim IP the attacker targets in case 2 (else auto) |
| `-Cases 1,4,5` | run a subset |
| `-Live` / `-DryRun` | send traffic / rehearse (default is dry-run-safe) |
| `-Provision` | set up the attacker box first |
| `-Domain`,`-DomainController`,`-LateralTarget`,`-SweepHosts` | override AD (cases 3–4) |
| `-WebPort <n>` | victim web-listener port for case 2 (default 8000) |

Run from an **elevated** PowerShell: case 2 opens a temporary victim web listener,
and cases 3/4 need admin for the RPC/WMI/DCOM/SchedTask calls.

## 3. What each part needs

- **Cases 1, 5** — only the attacker box + internet egress through the NGFW.
- **Case 2** — attacker-driven: the orchestrator starts a listener on the victim
  and has Kali run `attack-web.sh` against it. Needs the victim reachable from
  Kali on `-WebPort` (routing/NAT permitting) and SSH to Kali.
- **Cases 3, 4** — a real **DC / member servers** for the AD stages; pass
  `-DomainController` (and ideally `-LateralTarget` / `-SweepHosts` with real
  member servers, since "to multiple hosts" detectors want several IPs).

## 4. The one hard requirement

All victim⇄attacker and victim→DC traffic **must traverse your Palo Alto NGFW**
with **EAL enabled** and **log forwarding to Cortex XSIAM/XDR**. If the victim's
egress bypasses the firewall, nothing is logged. Verify routing first.

---

*Relationship to the other runners:* `Invoke-AttackLifecycle.ps1` is the
role-correct lifecycle orchestrator (attacker + victim). `Run-Scenarios.ps1`
(see `README-scenarios.md`) is the simpler "point everything at one server" runner.
Individual cases still run on their own via each `case-N\Start-Demo.cmd`.
