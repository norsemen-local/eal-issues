# Case 10 — Tunnels & Shadows (Covert Ops & Persistence)

**Story.** A quiet, tunnel-heavy intrusion. **Start:** the user is phished.
**Middle:** the implant opens an uncommon SSH session on a non-standard port,
turns it into a long high-volume tunnel for exfil, and hides extra beacons among
connections to obscure advertising domains. **End:** it plants persistence by
creating a scheduled task on a remote host over RPC.

- **Roles:** Kali = attacker / SSH-tunnel endpoint; this Windows host = victim;
  a remote host is the persistence target. Every stage is a **PAN Firewall EAL**
  log.
- New story case — see [`../README.md`](../README.md).

---

## 1. Attack flow → EAL rules

```
   (1) PHISHING ─▶ (2) uncommon SSH ─▶ (3) SSH tunnel volume ─▶ (4) rare ad domains ─▶ (5) remote schtask
   VICTIM ──SSH / DNS / HTTP / MSRPC──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR
```

| # | Stage (arc) | What the victim does | EAL alert | Rule id | Technique |
|---|-------------|----------------------|-----------|---------|-----------|
| 1 | **Start — Initial Access** | Phishing / drive-by | Phishing site access + malware URL | *(URL Filtering)* | T1566 |
| 2 | **Middle — Covert channel** | SSH session to a non-standard port | **Uncommon SSH session was established** | `18f84dd7` | T1071 · T1571 |
| 3 | **Middle — Covert channel** | Long, high-volume SSH tunnel | **Unusual SSH Activity** | `f1545c54` | T1572 |
| 4 | **Middle — Stealth C2** | Many connections to obscure ad domains | **Rare access to known advertising domains** | *(enable if off)* | T1071 · T1176.001 |
| 5 | **End — Persistence** | Remote scheduled task via RPC | **Rare Scheduled Task RPC activity from a rarely seen host** | *(enable if off)* | T1053 |

> Stages 2–3 use **enabled** SSH rules. Stages 4–5 use detectors that may need
> enabling in your tenant — the traffic generates regardless.

## The XDR endpoint layer (the other half of the story)

| Stage | Endpoint action | XDR analytic |
|-------|-----------------|-------------|
| 2–3 | SSH to a non-standard port | *Uncommon SSH session established* |
| 4 | default file-association hijack | *Manipulation of default file association configuration* |
| 5 | remote scheduled task via RPC | *Uncommon remote scheduled task creation* / *LOLBIN execution by scheduled task* |

**Story:** the implant tunnels over an uncommon SSH channel (endpoint+network),
hijacks a file association for stealth persistence (endpoint), hides beacons in
rare ad domains (network), and plants a remote scheduled task (endpoint+network).

---

## Detection model
Stages 3–4 resolve category-matched **DNS-Security test domains**
(`test-dnstun`, `test-adtracking` `.testpanw.com`) → **instant, firewall-sourced
PAN NGFW** detections, no baseline. The SSH behavioural analytics (`18f84dd7`,
`f1545c54`) are **baseline** detectors (30-day train / 14-day activate) and the
ad-domain / rarely-seen-host detectors may need enabling — those are the bonus
layer that matures over time; the DNS-Security anchors are the reliable backbone.

---

## 2. Run it
```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 10 -Live
```
Or standalone: **`case-10\Start-Demo.cmd`** → **[1] Configure** (attacker, SSH
port, remote host) → **[2] → [3] → [4]**. Stage 5 needs admin on the remote host.

## 3. Expected in Cortex XSIAM / XDR
| Stage | Alert | Rule id |
|-------|-------|---------|
| 2 | Uncommon SSH session was established | `18f84dd7` |
| 3 | Unusual SSH Activity | `f1545c54` |
| 4 | Rare access to known advertising domains | *(enable if off)* |
| 5 | Rare Scheduled Task RPC activity from a rarely seen host | *(enable if off)* |

See [`docs/verification-checklist.md`](docs/verification-checklist.md).

## 4. Real vs simulated — will the FW / XDR agent actually recognise this?

**Legend** — ✅ **REAL·instant (FW)**: signature/category, fires first-run. 🟡
**REAL·baseline (EAL)**: genuine traffic the analytic models, fires only after the
baseline matures. 🔵 **REAL·endpoint (XDR agent BIOC)**: real host action the agent
observes. 🟠 **SIMULATED**: approximation only.

| # | Stage | What the code ACTUALLY sends | Detection | Class | Source |
|---|-------|------------------------------|-----------|-------|--------|
| 1 | Phishing / drive-by IA | Real GETs to PANW URL-Filtering test pages + attacker-IP fetch | Phishing/malware URL categorisation | ✅ **REAL·instant** | FW (URL Filtering) |
| 2 | Uncommon SSH | Real TCP connect to attacker :2201–2203, reads the server banner, writes `SSH-2.0-CovertOps_0.9` — **raw socket from powershell.exe, no key exchange / not real SSH** | Uncommon SSH session `18f84dd7` | 🟡 **REAL·baseline** (App-ID may class it `ssh` by banner) | FW (EAL) |
| 3 | SSH tunnel volume | **Real bytes on the wire**: writes 256 KB + 384 KB random data over the TCP stream + holds it **+** `test-dnstun`.testpanw.com | Unusual SSH Activity `f1545c54` (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (volume real; not an encrypted SSH tunnel) (+ ✅ anchor) | FW (EAL / DNS-Sec) |
| 4a | File-assoc hijack (endpoint) | **Real** HKCU `.eal` + `ealfile\shell\open\command` → `powershell … IEX`, then reverted | Manipulation of default file association | 🔵 **REAL·endpoint** | XDR agent (BIOC) |
| 4b | Rare ad domains | DNS + `GET px?cid=…` to 8 **real known** ad/tracking domains (doubleclick, googlesyndication, scorecardresearch, adnxs, adsrvr, taboola, criteo, moatads) **+** `test-adtracking`.testpanw.com | Rare access to known advertising domains | 🟡 **REAL·baseline** (real ad-category hits; rarity is baseline) (+ ✅ anchor) | FW (EAL / DNS-Sec) |
| 5 | Remote scheduled task | **Real** `schtasks /create /run /delete /s <target>` (ATSVC MSRPC) — errors swallowed; lands only if target reachable + admin | Rare Scheduled Task RPC from a rarely-seen host (T1053) | 🟡 **REAL·baseline** — **agent-shadowed on the target** | FW (EAL) + XDR agent on target |

**Bottom line:** the instant, reliable hits are stage 1 (phishing) and the
`test-dnstun` / `test-adtracking` DNS-Security anchors; plus the stage-4a
file-association BIOC on the agent. The SSH stages push **real byte volume** over a
real socket, but it is a **raw powershell.exe banner exchange, not encrypted SSH** —
App-ID must hold `ssh` and the 30-day baseline must mature for `18f84dd7`/`f1545c54`
to fire, and only if the attacker's port is actually listening. **Stage 4b now uses
real known advertising domains** (doubleclick, googlesyndication, …) so the ad
category genuinely matches and "Rare access to known advertising domains" has real
known-ad-domain hits to key on (rarity is baseline); the `test-adtracking` anchor
still gives the instant firewall detection. Stage 5 **does really create**
the remote task via the `schtasks.exe` LOLBIN (an agent on the target out-races the
firewall analytic — genuine agent-shadowing), but on an unreachable host or without
admin it emits only an RPC attempt. Note: README's "Uncommon SSH session" *agent*
analytic for stages 2–3 does **not** actually fire — the traffic comes from
powershell.exe, not `ssh.exe`, and `_endpoint.ps1` has no SSH function, so those two
are firewall-only in practice.

---

## 5. Safety
SSH banner/tunnel traffic to your lab attacker, benign DNS/HTTP to made-up ad
domains, and a create-then-delete remote task. `DryRun` sends nothing. Authorized
labs only.
