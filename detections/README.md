# Splunk detections

Six Splunk searches, one per technique, each written against the exact Windows event the attack
produces and tuned on the lab's own telemetry. Each `.spl` file opens with a comment block
explaining the data source and the detection logic.

| File | Technique | Event | The signal |
|------|-----------|-------|-----------|
| [`01-kerberoasting.spl`](01-kerberoasting.spl) | T1558.003 | Security 4769 | **RC4** service ticket (`0x17`) for a user service-account in an otherwise-AES domain |
| [`02-password-spraying.spl`](02-password-spraying.spl) | T1110.003 | Security 4625 | one source → **≥5 distinct accounts** in a 10-minute window |
| [`03-dcsync.spl`](03-dcsync.spl) | T1003.006 | Security 4662 | replication extended-right GUIDs exercised by a **non-DC** account |
| [`04-pass-the-hash.spl`](04-pass-the-hash.spl) | T1550.002 | Security 4624 | privileged account over **NTLM** network logon (`NtLmSsp`, type 3) |
| [`05-scheduled-task.spl`](05-scheduled-task.spl) | T1053.005 | Sysmon 1 / Security 4698 | `schtasks /create` process creation + task registration |
| [`06-account-discovery.spl`](06-account-discovery.spl) | T1087.002 | Sysmon 1 | burst of `net`/AD recon commands from one host/user |

## Notes from building these

- **Field extraction matters.** Sysmon was first forwarded as XML, so `CommandLine`/`Image` did not
  auto-extract and the Sysmon detections returned nothing. Switching the Universal Forwarder to the
  classic event format (`renderXml = 0`) fixed the Sysmon searches with no add-on required.
- **The DCSync GUID is in the event body, not a clean field.** Splunk extracts `Properties` on 4662
  as just `Control Access`, so the replication GUID is matched as a full-text `TERM()` instead.
- **Modern Kerberos defaults to AES**, so a single RC4 service ticket is a high-signal Kerberoast
  indicator; the lab's `svc_sql` account is pinned to RC4 to model a legacy service account.
- **Pass-the-hash shows `Key_Length=128`, not 0** on this build, so the detection keys on the NTLM
  network-logon pattern for a privileged account rather than a zero key length.

Each search is written as an ad-hoc search but is ready to be saved as a scheduled alert
(`index=winlogs` + the stats pattern), which is how it would run in a real SOC.
