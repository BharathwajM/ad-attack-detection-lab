# Sigma rules

The same detections as [`detections/`](../detections/), written in [Sigma](https://sigmahq.io/), the vendor-neutral rule format. A Sigma rule can be converted to the query language of most SIEMs, including Splunk, Microsoft Sentinel (KQL) and Elastic.

| Rule | Technique | Level | Type |
|---|---|---|---|
| [`01-kerberoasting.yml`](01-kerberoasting.yml) | T1558.003 | High | Single event |
| [`02-password-spraying.yml`](02-password-spraying.yml) | T1110.003 | Medium | Correlation: 5+ accounts from one source in 10 minutes |
| [`03-dcsync.yml`](03-dcsync.yml) | T1003.006 | Critical | Single event |
| [`04-pass-the-hash.yml`](04-pass-the-hash.yml) | T1550.002 | Low (hunt) | Single event |
| [`04b-unexpected-privileged-ntlm.yml`](04b-unexpected-privileged-ntlm.yml) | T1550.002 | High (lab only) | Single event |
| [`05-scheduled-task.yml`](05-scheduled-task.yml) | T1053.005 | Medium | Single event |
| [`06-account-discovery.yml`](06-account-discovery.yml) | T1087.002 | Low | Correlation: 2+ different commands by one user on one host in 1 hour |

Password spraying and account discovery count events over a time window, so they use [Sigma correlation rules](https://github.com/SigmaHQ/sigma-specification) with a base rule in the same file.

## Checked in CI

The [Sigma rules workflow](../.github/workflows/sigma.yml) runs on every change to this folder:

1. `sigma check` validates each rule against the Sigma specification and ATT&CK tags. The job fails on any error or warning.
2. `sigma convert --target splunk --pipeline splunk_windows` converts every rule to SPL. The output appears as annotations on each run.

The first CI run caught an outdated ATT&CK tactic tag on the two pass-the-hash rules, which I then removed.

## Differences from the lab's SPL

- **Field names.** The rules use Sigma's standard Windows field names (`TargetUserName`, `IpAddress`, `CommandLine`). The lab's Splunk extracts classic-format events with different names (`Account_Name`, `Source_Network_Address`, `Process_Command_Line`), so running the converted SPL against `index=winlogs` would need a field-mapping pipeline.
- **Process creation.** Rules 05 and 06 use Sigma's `process_creation` category. Converters map that to Sysmon event 1 or Security event 4688, depending on the pipeline. The lab used 4688.
- **Account discovery window.** The SPL version counted commands over whatever time range was searched. The Sigma version needs a fixed window, so I used 1 hour.

These rules were converted and validated in CI but not run against the lab data, because the lab VMs are shut down. The SPL in `detections/` is the version tested against the captured attacks.
