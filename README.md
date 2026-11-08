# Active Directory Attack & Detection Lab

A self-contained Active Directory lab built to **run real attacker techniques and then detect them in Splunk**. I built the domain, generated the telemetry (Windows Security events + Sysmon), executed six MITRE ATT&CK techniques, and wrote and validated a Splunk detection for each one against the logs they produced.

This is the companion to my [SOC monitoring lab](https://github.com/BharathwajM/soc-portfolio-lab) (Microsoft Sentinel, honeypot, Defender for Endpoint). That project was cloud detection-as-a-service; this one is **the endpoint/identity layer** — the host and domain-controller telemetry a SOC analyst actually triages, and the detection engineering behind it.

---

## Lab architecture

| Host | OS | Role | IP |
|------|----|----|----|
| **DC01** | Windows Server 2025 | Domain controller — `soclab.local`, DNS, audit policy | 10.10.10.10 |
| **WS01** | Windows 11 Enterprise | Domain-joined workstation (attacker's foothold) | 10.10.10.20 |
| **SPLUNK01** | Ubuntu 24.04 | Splunk Enterprise SIEM + Linux attacker (impacket) | 10.10.10.30 |

All three run on an isolated VirtualBox NAT network (`10.10.10.0/24`). Logging pipeline:

```
 DC01 / WS01 ──► Sysmon (sysmon-modular config)  ─┐
             ──► Windows Security / PowerShell logs ─┼─► Splunk Universal Forwarder ─► SPLUNK01 :9997 ─► index=winlogs
```

- **Sysmon** (SwiftOnSecurity/olafhartong `sysmon-modular`) for rich process-creation, network and image-load telemetry.
- **Audit policy** tuned on the DC so the identity attacks are visible: Kerberos service-ticket operations (4769), DS access (4662), logon (4624/4625), and process creation **with command line** (4688).
- **Splunk Universal Forwarder** on each Windows host shipping Security, System, Sysmon and PowerShell Operational channels.

---

## Techniques executed & detected

Each technique was run in the lab and then caught by a purpose-built Splunk search. Full write-ups and screenshots are in [`docs/`](docs/); the searches are in [`detections/`](detections/).

| # | Technique | ATT&CK ID | Run from | Primary data source | Detection logic |
|---|-----------|-----------|----------|--------------------|-----------------|
| 1 | Kerberoasting | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | WS01 | Security 4769 | One account, many SPNs, **RC4** tickets (0x17) |
| 2 | Password Spraying | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) | WS01 | Security 4625 | One source → many accounts, short window |
| 3 | DCSync | [T1003.006](https://attack.mitre.org/techniques/T1003/006/) | SPLUNK01 (impacket) | Security 4662 | Replication rights by a **non-DC** account |
| 4 | Pass-the-Hash | [T1550.002](https://attack.mitre.org/techniques/T1550/002/) | SPLUNK01 (impacket) | Security 4624 | NTLM network logon, `Key_Length=0`, NtLmSsp |
| 5 | Scheduled Task | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | WS01 | Sysmon 1 + Security 4698 | `schtasks /create` + task registration |
| 6 | Account Discovery | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | WS01 | Sysmon 1 | Burst of `net`/AD recon commands |

---

## What this demonstrates

- **Detection engineering end to end** — generate the attack telemetry, understand the event that proves it, write the search, tune out the noise, validate against ground truth.
- **Reading AD telemetry the way a SOC analyst does** — 4769 encryption types, 4662 replication GUIDs, NTLM logon tells, Sysmon command-line context.
- **Mapping to MITRE ATT&CK** so detections are measured against a real adversary framework.
- **Building infrastructure** — unattended VM provisioning, a domain, a SIEM pipeline — reproducibly from scripts.

## Build it yourself

Everything is scripted in [`build/`](build/) (VM creation and unattended installs, DC promotion, Sysmon + forwarder deployment) and [`attacks/`](attacks/) (the technique runners). The lab passwords live in a gitignored `lab-credentials.local.txt` that each script reads — nothing secret is committed.

> Built on local VirtualBox VMs. Evaluation editions of Windows Server 2025 and Windows 11 Enterprise; all attacks were run only inside this isolated lab network.
