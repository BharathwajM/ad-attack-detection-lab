# Triage playbooks

One playbook per alert, written for a Tier 1 SOC analyst. Each one covers what the alert means, how to check it, what usually explains it, when to escalate, and what to record in the ticket. Containment steps are listed for the Tier 2 or incident response team.

| Playbook | ATT&CK | Suggested severity | Detection |
|---|---|---|---|
| [Kerberoasting](01-kerberoasting.md) | T1558.003 | High | [01-kerberoasting.spl](../detections/01-kerberoasting.spl) |
| [Password spraying](02-password-spraying.md) | T1110.003 | Medium (High if a logon succeeds) | [02-password-spraying.spl](../detections/02-password-spraying.spl) |
| [DCSync](03-dcsync.md) | T1003.006 | Critical | [03-dcsync.spl](../detections/03-dcsync.spl) |
| [Pass-the-hash](04-pass-the-hash.md) | T1550.002 | High (tuned alert) | [04](../detections/04-pass-the-hash.spl), [04b](../detections/04b-unexpected-privileged-ntlm.spl) |
| [Scheduled task](05-scheduled-task.md) | T1053.005 | Medium | [05-scheduled-task.spl](../detections/05-scheduled-task.spl) |
| [Account discovery](06-account-discovery.md) | T1087.002 | Low on its own | [06-account-discovery.spl](../detections/06-account-discovery.spl) |

## How the alerts connect

In a real queue these would arrive as separate alerts. Put on one timeline, the captured lab results tell a single story. All times are 8 November 2026, taken from the [evidence files](../evidence/).

| Time | Alert | What it shows |
|---|---|---|
| 07:10 | Password spraying | 37 failed logons against 5 accounts, reported from workstation WS01 |
| 07:13 to 07:27 | NTLM logons to DC01 | Administrator logging on to DC01 over NTLM from 10.10.10.20 (WS01) and 10.10.10.30 (SPLUNK01) |
| 07:19 to 07:27 | **DCSync** | Administrator used replication rights on DC01 102 times |
| 07:26 to 07:37 | Kerberoasting | `jsmith` on WS01 requested 3 RC4 tickets for `svc_sql` |
| 07:27:28 | Pass-the-hash | Administrator logged on to WS01 over NTLM from 10.10.10.30 |
| 07:37:15 | Account discovery and scheduled task | `jsmith` on WS01 ran 4 domain discovery commands (10 process events, because `net` starts `net1`), then created task `ATOMIC-T1053` |

Two pivots link everything: the user `jsmith` on WS01, and the Administrator account used from 10.10.10.30. An analyst who triaged the Kerberoasting alert on its own would miss that DCSync, the most serious alert here, had started six minutes earlier. That is why each playbook asks you to search for other alerts on the same user, host and source IP.

The lab ran these techniques from scripts, so the order is not a real intrusion. The triage method is the same.

## About the pivot searches

The searches in each playbook use the same index and field names as the validated detections (`index=winlogs`, `Account_Name`, `Source_Network_Address`, `Process_Command_Line` and so on). I wrote them after the lab VMs were shut down, so they have not been run against the lab data. Set the time picker to about an hour either side of the alert before running them.
