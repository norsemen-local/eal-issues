# Running the scenarios (automatic parameters + Linux target)

Two helpers drive the whole demo without editing any per-case config:

- **`Run-Scenarios.ps1`** (Windows) — auto-fills every case's parameters and runs
  the scenarios. Internet-facing stages (web / FTP / SSH / ICMP / SMB / exfil) are
  pointed at your **Linux target server**; internal AD stages (LDAP / RPC /
  Kerberos) are auto-detected from this machine's domain.
- **`target-server/setup-target-server.sh`** (Linux) — stands up benign "victim"
  services on the target so the attacks hit **real listeners** and produce
  complete sessions (much stronger EAL signals than traffic to a dead IP).

Default target server: **`170.187.158.212`** (override with `-TargetServer`).

---

## 1. Provision the Linux target (once)

On the server (as root):
```bash
sudo bash setup-target-server.sh          # start HTTP:80, FTP:21(anon), SSH:2201-2203, SMB share
sudo bash setup-target-server.sh stop     # tear everything down
```
It installs `python3`, `pyftpdlib`, `socat` (and `samba` on Debian/Ubuntu) and
starts:

| Service | Port(s) | Used by |
|---------|---------|---------|
| HTTP request logger | 80 | case 1 IA, case 2 (all), case 3 IA (web exploit / exfil / beacon) |
| Anonymous FTP | 21 | case 4 IA, case 5 stages 1–2 |
| SSH (same host key on 3 ports via socat → :22) | 2201–2203 | case 5 stages 3–4 (uncommon SSH / same key / downgrade) |
| SMB guest share `//<ip>/share` | 445 | case 5 stage 6 (rare SMB transfer) |
| ICMP | — | case 5 stage 5 (no service needed) |

> The server's **cloud firewall / security group must allow inbound** 21, 80,
> 445, 2201–2203. The script opens the host `ufw` if present, but a Linode/AWS
> security group is separate.

Or let the orchestrator push + run it for you (needs your SSH auth to the box):
```powershell
.\Run-Scenarios.ps1 -SetupServer -Live
```

---

## 2. Run the scenarios (Windows attacker host)

```powershell
cd D:\PANW\eal-demo
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

.\Run-Scenarios.ps1 -DryRun                 # rehearse everything, send NO traffic
.\Run-Scenarios.ps1 -Cases 1,2,5 -Live      # internet-only cases, for real
.\Run-Scenarios.ps1 -Live -PauseBetween     # all 5, pause between stages
.\Run-Scenarios.ps1 -SetupServer -Live      # provision the server then run all
```

Useful switches:

| Switch | Effect |
|--------|--------|
| `-TargetServer <ip>` | target server for internet-facing stages (default `170.187.158.212`) |
| `-Cases 1,2,5` | run a subset |
| `-Live` | actually send traffic (default is dry-run-safe) |
| `-DryRun` | force dry-run |
| `-PauseBetween` | pause between stages |
| `-SetupServer` | scp + run the Linux setup script first |
| `-DomainController`, `-Domain`, `-LateralTarget`, `-SweepHosts` | override the AD auto-detect (cases 3/4) |

The orchestrator writes each case's `config/lab-config.local.ps1` automatically,
so you never hand-edit config. Re-running overwrites it.

---

## 3. What the server can and cannot do

**It makes these land for real** (complete sessions → strong EAL signals):
- Web exploitation (Spring4Shell / traversal / params) — cases 1,2,3 IA
- Anonymous + brute FTP — cases 4,5
- SSH banner / downgrade / same-host-key (3 ports) — case 5
- HTTP exfil / beacon / rare-UA — cases 1,2
- SMB transfer — case 5

**It cannot stand in for internal AD infrastructure.** These stages still need a
real lab **DC / member servers**, because they target domain services, not an
internet host:
- Case 3 stages 2–6 (RPC sweep, sensitive RPC, DCOM, WinRM, SVCCTL/SchedTask)
- Case 4 stages 2–6 (LDAP, WPAD, EFSRPC, DCSync, Bronze Bit)

For those, pass `-DomainController` / `-LateralTarget` / `-SweepHosts` (or let
auto-detect fill them from a domain-joined attacker host).

**A single server can't satisfy "to multiple hosts" detectors** (Abnormal RPC to
multiple hosts, Abnormal ICMP echo to multiple hosts) — those need several
distinct destination IPs. The scripts warn when everything collapses to one IP.

---

## 4. The one hard requirement

The attacker host's traffic to the target server (and to the DC) **must traverse
your Palo Alto NGFW**, with **EAL enabled** and **log forwarding to Cortex
XSIAM/XDR**. If the Windows host reaches `170.187.158.212` over an egress path
that bypasses the firewall, the firewall never sees it and no EAL alert fires —
verify egress routing first.
