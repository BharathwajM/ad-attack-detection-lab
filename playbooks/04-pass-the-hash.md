# Playbook: Pass-the-hash (privileged NTLM logon)

| | |
|---|---|
| **Detections** | [04b-unexpected-privileged-ntlm.spl](../detections/04b-unexpected-privileged-ntlm.spl) is the alert. [04-pass-the-hash.spl](../detections/04-pass-the-hash.spl) is the broader hunt. |
| **ATT&CK** | T1550.002, Use Alternate Authentication Material: Pass the Hash |
| **Suggested severity** | High for the tuned alert. The broad hunt is for scheduled review, not paging. |
| **Data** | Security 4624 (successful logon), type 3, NTLM, `NtLmSsp` |

## What the alert means

The Administrator account logged on to WS01 over the network with NTLM, from a source other than the approved admin host (DC01). Someone holding a stolen NT hash can log on this way without knowing the password.

Event 4624 cannot tell a typed password from a replayed hash. The alert is about **who, from where, to where**: a privileged account arriving from a host it does not normally use. The [tuning replay](../docs/walkthrough.md#tuning-replay) shows the benign cases this alert filters out.

## Lab example

Administrator logged on to WS01 over NTLM from 10.10.10.30 (SPLUNK01) at 07:27:28 ([evidence](../evidence/04-pass-the-hash.txt)). SPLUNK01 is a Linux server, so it has no reason to make an admin SMB connection to a workstation.

## Triage steps

1. **What is the source?** Map `src_ip` to a hostname and owner. Is it an admin jump host, a server, a workstation or unknown?
2. **Does this account normally come from there?** Compare with the account's usual sources and whether it normally uses Kerberos (pivot below).
3. **Is the source host already suspicious?** Look for other alerts on the same IP, especially DCSync, spraying or new logons to several machines.
4. **What happened on the destination after the logon?** Check process creation on WS01 in the minutes after.
5. **Is the same hash being used elsewhere?** NTLM logons by the same account from the same IP to several hosts suggests lateral movement.

## Pivot searches

How this account usually logs on, by source and protocol:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4624 Account_Name="Administrator"
| stats count by Source_Network_Address, Authentication_Package, ComputerName
```

Every NTLM network logon from the suspicious source:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4624 Logon_Type=3 Authentication_Package=NTLM Source_Network_Address="10.10.10.30"
| eval target=mvindex(Account_Name, -1)
| stats count min(_time) as first_seen max(_time) as last_seen by target, ComputerName
| convert ctime(first_seen) ctime(last_seen)
```

Processes on the destination after the logon:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4688 host="WS01"
| table _time Account_Name Process_Command_Line
```

## Likely benign causes

- An admin connecting from a new or unregistered admin host
- A legacy application or file share that only supports NTLM
- An IP-address connection (`\\10.10.10.20\share`) instead of a hostname, which forces NTLM even for normal users

## Verdict

**Escalate** if the source is not an approved admin host, the source has other alerts, or the account logged on to several hosts from the same source in a short time.

**Close as benign** if the admin confirms the connection through a separate channel (not by replying to an alert email), and the source is a known admin host that should be added to the baseline.

## Containment (Tier 2 / IR)

- Isolate the source host.
- Reset the account's password, which changes its NT hash. Check whether the same local Administrator password is reused across machines, and use LAPS if it is.
- Review every host the account logged on to from the source.

## Record in the ticket

Account, source IP and hostname, destination, logon time, whether the source is approved, other hosts reached, related alerts, and the verdict with reasons.
