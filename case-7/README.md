# Case 7 — Poisoned Well (Rogue Software-Update Hijack)

**Story.** A supply-chain-style intrusion. **Start:** the user is phished.
**Middle:** the attacker redirects the victim's software-update traffic to a
**rogue update server**, delivers a trojanized "update" over **plain HTTP**, and
an **unmanaged device model** shows up speaking the update protocol. **End:** the
fake update runs and beacons out to the attacker's rare C2 domain.

- **Roles:** Kali = rogue update server + C2; this Windows host = victim.
  Every stage is a **PAN Firewall EAL** log.
- New story case — see [`../README.md`](../README.md).

---

## 1. Attack flow → enabled EAL rules

```
  VICTIM ──MS-Update / HTTP──▶ PAN NGFW (EAL) ──▶ Cortex XSIAM/XDR     ATTACKER=rogue update server
  (1) PHISHING ─▶ (2) rogue update server ─▶ (3) update over HTTP ─▶ (4) unmanaged model ─▶ (5) trojan C2
```

| # | Stage (arc) | What the victim does | EAL alert | Rule id | Technique |
|---|-------------|----------------------|-----------|---------|-----------|
| 1 | **Start — Initial Access** | Phishing / drive-by | Phishing site access + malware URL | *(URL Filtering)* | T1566 |
| 2 | **Middle — Update hijack** | WSUS/Windows-Update requests to a rare server | **Rare MS-Update Server was detected** | `3d068240` | T1199 |
| 3 | **Middle — Delivery** | Trojanized update over plain HTTP | **Rare MS-Update traffic over HTTP** | `a3602352` | T1210 |
| 4 | **Middle — Rogue device** | Unmanaged device model on the update protocol | **Unique client computer model via MS-Update protocol** | `59b720f1` | T1200 |
| 5 | **End — Payload C2** | Fake update beacons to a rare domain | **Abnormal Communication to a Rare Domain** | `c2da63d1` | T1071 |

## The XDR endpoint layer (the other half of the story)

| Stage | Endpoint action | XDR analytic |
|-------|-----------------|-------------|
| 3 | install a rogue **root CA** + drop payload in AppData | *Root certificate installed*; *Suspicious file created in AppData directory* |
| 5 | `bitsadmin` LOLBIN fetch | *LOLBIN connected to a rare external host* |

**Story:** the trojanized update installs its own root CA (so its fake binaries
are "trusted"), drops a payload, and the payload pulls its next stage via a
LOLBIN — while the network side shows the rogue MS-Update server + C2. *(Stage 3
root-CA install needs admin.)*

---

## Detection model
Each stage resolves a category-matched Palo Alto **DNS-Security test domain**
(`test-fake-software`, `test-malware`, `test-c2` `.testpanw.com`) → an **instant,
firewall-sourced PAN NGFW** detection, no baseline. The MS-Update EAL analytics
(`3d068240`/`a3602352`/`59b720f1`) are **baseline** detectors (30-day train / 14-day
activate) and surface later — they are the bonus layer, not the backbone.

---

## 2. Run it
```powershell
.\Invoke-AttackLifecycle.ps1 -Cases 7 -DryRun
.\Invoke-AttackLifecycle.ps1 -Cases 7 -Live
```
Or standalone: **`case-7\Start-Demo.cmd`**. MS-Update traffic uses `http://` so
the firewall app-ID's it without decryption.

## 3. Expected in Cortex XSIAM / XDR
| Stage | Alert | Rule id |
|-------|-------|---------|
| 2 | Rare MS-Update Server was detected | `3d068240` |
| 3 | Rare MS-Update traffic over HTTP | `a3602352` |
| 4 | Unique client computer model via MS-Update protocol | `59b720f1` |
| 5 | Abnormal Communication to a Rare Domain | `c2da63d1` |

See [`docs/verification-checklist.md`](docs/verification-checklist.md).

## 4. Real vs simulated — will the FW / XDR agent actually recognise this?

**Legend** — ✅ **REAL·instant (FW)**: signature/category, fires first-run. 🟡
**REAL·baseline (EAL)**: genuine traffic the analytic models, fires only after the
baseline matures. 🔵 **REAL·endpoint (XDR agent BIOC)**: real host action the agent
observes. 🟠 **SIMULATED**: approximation only.

| # | Stage | What the code ACTUALLY sends | Detection | Class | Source |
|---|-------|------------------------------|-----------|-------|--------|
| 1 | Phishing / drive-by IA | Real GETs to PANW URL-Filtering test pages + attacker-IP fetch | Phishing/malware URL categorisation | ✅ **REAL·instant** | FW (URL Filtering) |
| 2 | Rogue MS-Update server | **Genuine** `Windows-Update-Agent/10.0…` UA + real WSUS paths (`/ClientWebService/client.asmx`, `/selfupdate/*.cab`) to the attacker IP over http **+** `test-fake-software`.testpanw.com | Rare MS-Update Server `3d068240` (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (+ ✅ anchor) | FW (EAL / DNS-Sec) |
| 3 | MS-Update over HTTP | Real WUA-UA GETs to `/Content/Updates/*.exe/.cab` (+ Range header) and a `SyncUpdates` SOAPAction POST **+** `test-malware`.testpanw.com | Rare MS-Update over HTTP `a3602352` (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (+ ✅ anchor) | FW (EAL / DNS-Sec) |
| 3e | Trust tamper (endpoint) | **Real** self-signed cert + `certutil -addstore Root` (needs admin) + AppData `.ps1` drop | Root certificate installed; Suspicious AppData file | 🔵 **REAL·endpoint** | XDR agent (BIOC) |
| 4 | Unmanaged device model | 3 POSTs with a custom `X-Device-Model` / `X-WSUS-DeviceModel` header + body — **no test-domain anchor, and headers can't populate the native WSUS inventory field the analytic reads** | Unique client computer model `59b720f1` | 🟠 **SIMULATED** | FW (EAL) |
| 5 | Trojan C2 beacon | 8 real DNS + `GET /report?...` to `poisoned-update-c2.net` **+** `test-c2`.testpanw.com | Abnormal Comms to a Rare Domain `c2da63d1` (+ ✅ DNS-Sec) | 🟡 **REAL·baseline** (+ ✅ anchor) | FW (EAL / DNS-Sec) |
| 5e | LOLBIN fetch (endpoint) | **Real** `bitsadmin /transfer … /download` from the C2 domain | LOLBIN connected to a rare external host | 🔵 **REAL·endpoint** | XDR agent (BIOC) |

**Bottom line:** the MS-Update traffic is **authentic** (real WUA User-Agent, real
WSUS paths, a real SOAP body — not a generic GET), so stages 2–3 genuinely feed
their analytics once baselined, and the first-run backbone is the URL-Filtering +
`test-*.testpanw.com` DNS-Security hits plus the endpoint BIOCs (root-CA, AppData,
`bitsadmin`, if an agent is present). **Stage 4 is the one cosmetic gap** — the
"unique device model" lives only in HTTP headers, which cannot populate the WSUS
inventory record the exact analytic reads, and it has **no instant anchor**, so it
is the least likely stage to produce a real alert.

---

## 5. Safety
Benign HTTP requests mimicking the update protocol (dummy payloads, no real
binaries). `DryRun` sends nothing. The "unmanaged device model" stage advertises
the model in request metadata — a best-effort approximation of the WSUS inventory
field. Authorized labs only.
