# Splunk detections

Six technique hunts and one tuned lab alert, each written against the Windows event the attack
produces and tuned on the lab's own telemetry. Each `.spl` file opens with a comment block
explaining the data source and the detection logic.

| File | Technique | Event | The signal |
|------|-----------|-------|-----------|
| [`01-kerberoasting.spl`](01-kerberoasting.spl) | T1558.003 | Security 4769 | **RC4** service ticket (`0x17`) for a user service-account in an otherwise-AES domain |
| [`02-password-spraying.spl`](02-password-spraying.spl) | T1110.003 | Security 4625 | one source → **≥5 distinct accounts** in a 10-minute window |
| [`03-dcsync.spl`](03-dcsync.spl) | T1003.006 | Security 4662 | replication extended-right GUIDs exercised by a **non-DC** account |
| [`04-pass-the-hash.spl`](04-pass-the-hash.spl) | T1550.002 | Security 4624 | non-machine account over **NTLM** network logon (`NtLmSsp`, type 3), possible pass-the-hash |
| [`04b-unexpected-privileged-ntlm.spl`](04b-unexpected-privileged-ntlm.spl) | T1550.002 | Security 4624 | lab Administrator NTLM on WS01 from an unexpected IP; [replayed on three captured test cases](../docs/walkthrough.md#tuning-replay) |
| [`05-scheduled-task.spl`](05-scheduled-task.spl) | T1053.005 | Security 4688 | `schtasks /create` or `Register-ScheduledTask` in the command line |
| [`06-account-discovery.spl`](06-account-discovery.spl) | T1087.002 | Security 4688 | two or more distinct AD discovery command lines per host/account in the search range |

## Notes from building these

- **Field extraction matters.** Sysmon was first forwarded as XML, so `CommandLine`/`Image` did not
  auto-extract and the Sysmon detections returned nothing. Switching the Universal Forwarder to the
  classic event format (`renderXml = 0`) and using Security 4688 with command-line auditing restored coverage for the two process-creation searches.
- **The DCSync GUID is in the event body, not a clean field.** Splunk extracts `Properties` on 4662
  as just `Control Access`, so the replication GUID is matched as a full-text `TERM()` instead.
- **Modern Kerberos defaults to AES**, so a single RC4 service ticket is a high-signal Kerberoast
  indicator; the lab's `svc_sql` account is pinned to RC4 to model a legacy service account.
- **The pass-the-hash emulation showed `Key_Length=128`.** The search has no key-length or group-membership filter. See the [NTLM comparison](../docs/walkthrough.md#4-possible-pass-the-hash-t1550002) for what a match means.

Each detection has a matching [triage playbook](../playbooks/) for the analyst who receives the alert, and a [Sigma version](../sigma/) for other SIEMs.

These are ad hoc lab searches. Before scheduling an alert, set a lookback and baseline legitimate activity for that environment.
