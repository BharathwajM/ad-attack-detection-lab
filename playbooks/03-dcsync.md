# Playbook: DCSync

| | |
|---|---|
| **Detection** | [03-dcsync.spl](../detections/03-dcsync.spl) |
| **ATT&CK** | T1003.006, OS Credential Dumping: DCSync |
| **Suggested severity** | Critical. Escalate straight away; do not wait to finish triage. |
| **Data** | Security 4662 on the domain controller (needs Directory Service Access auditing) |

## What the alert means

An account that is not a domain controller used the directory replication rights (`DS-Replication-Get-Changes` and `-All`). Tools like `secretsdump.py` and Mimikatz `lsadump::dcsync` use these rights to ask a DC for password hashes, including `krbtgt`. With the `krbtgt` hash an attacker can forge Kerberos tickets for any user.

Only DC machine accounts (ending in `$`) should replicate. If this alert is real, assume every password in the domain is exposed.

## Lab example

`Administrator` used replication rights on DC01 102 times between 07:19:58 and 07:27:30 ([evidence](../evidence/03-dcsync.txt)). In the same window, the [pass-the-hash evidence](../evidence/04-pass-the-hash.txt) shows Administrator NTLM logons to DC01 from 10.10.10.20 and 10.10.10.30. 10.10.10.30 is SPLUNK01, where `secretsdump.py` ran.

## Triage steps

1. **Which account?** Note `Account_Name`. Is it a known replication tool's service account, such as Azure AD Connect?
2. **Where did the session come from?** 4662 does not record the source IP. Find the matching 4624 logon on the DC for the same account around the same time (pivot below) and note the `Source_Network_Address`.
3. **Is that source a domain controller?** If the IP is not one of your DCs, treat the alert as a true positive.
4. **How did that account get onto the source host?** Check for pass-the-hash, spraying or Kerberoasting alerts involving the same account or IP.

## Pivot searches

Logons by the same account on the DC (to find the source IP):

```spl
index=winlogs source="WinEventLog:Security" EventCode=4624 ComputerName="DC01.soclab.local" Account_Name="Administrator"
| stats count min(_time) as first_seen max(_time) as last_seen by Source_Network_Address, Authentication_Package, Logon_Type
| convert ctime(first_seen) ctime(last_seen)
```

Everything else that source IP did:

```spl
index=winlogs source="WinEventLog:Security" Source_Network_Address="10.10.10.30"
| stats count by EventCode, ComputerName, Account_Name
```

## Likely benign causes

- A new domain controller being promoted (its machine account replicates, which the `$` filter already excludes)
- Azure AD Connect or another directory sync tool whose service account has replication rights. This should be a documented, known account from a known server.

## Verdict

**Escalate immediately as Critical** unless the account and source host exactly match a documented sync service. Do not contact the account owner first; that can tip off an attacker.

## Containment (Tier 2 / IR)

- Isolate the source host.
- Disable or reset the account that performed the replication.
- Reset the `krbtgt` password twice, with enough time between resets for replication, to invalidate forged tickets.
- Plan resets for all privileged accounts, and review who holds replication rights on the domain object.

## Record in the ticket

Account, DC, event count and time range, the source IP from the matching 4624, how the account was obtained (related alerts), and the time you escalated.
