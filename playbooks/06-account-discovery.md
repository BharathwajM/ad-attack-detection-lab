# Playbook: Domain account discovery

| | |
|---|---|
| **Detection** | [06-account-discovery.spl](../detections/06-account-discovery.spl) |
| **ATT&CK** | T1087.002, Account Discovery: Domain Account |
| **Suggested severity** | Low on its own. Raise it when it lines up with other alerts on the same user or host. |
| **Data** | Security 4688 (process creation with command line) |

## What the alert means

One user on one host ran two or more different domain discovery commands, such as `net user /domain`, `net group "Domain Admins" /domain`, `net accounts /domain` or `nltest /dclist`. After getting a foothold, attackers run these to learn who the admins are and what the password policy is.

IT staff run the same commands, so this alert is mostly useful as **context** for other alerts.

## Lab example

`jsmith` on WS01 ran 4 discovery commands within a quarter of a second at 07:37:15 ([evidence](../evidence/06-account-discovery.txt)). They appear as 10 process events because `cmd.exe` launched `net.exe`, which starts `net1.exe`. The same user created a scheduled task a tenth of a second later and had requested RC4 Kerberos tickets earlier.

## Triage steps

1. **Who ran it?** Is the user in IT or a helpdesk role, or a normal business user? Business users almost never run `net group /domain`.
2. **How fast?** Several commands within a second points to a script or tool, not a person typing.
3. **What did they look for?** Queries for `Domain Admins`, the password policy (`net accounts`) or the list of DCs (`nltest /dclist`) are what an attacker checks before choosing targets.
4. **What else happened on this host and user?** This is the main step. Look for Kerberoasting, spraying, new scheduled tasks or unusual logons in the hours around the alert.

## Pivot searches

One timeline of related activity for the user (Kerberos tickets, failed logons, processes):

```spl
index=winlogs source="WinEventLog:Security" (EventCode=4688 OR EventCode=4769 OR EventCode=4625) Account_Name="jsmith*"
| table _time host EventCode Service_Name Ticket_Encryption_Type Sub_Status Process_Command_Line
| sort _time
```

The same discovery commands from other users or hosts:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4688
    (Process_Command_Line="*net* group*/domain*" OR Process_Command_Line="*nltest*/dclist*")
| stats count values(Process_Command_Line) as commands by host, Account_Name
```

## Likely benign causes

- IT staff troubleshooting accounts or group membership
- Inventory, audit or monitoring scripts that run on a schedule (these repeat at the same time every day)
- Login scripts that query the domain

## Verdict

**Escalate** if the user is not in IT, the commands ran as a fast burst, or the same user or host has any other alert. In the lab, all three were true.

**Close as benign** if the user is IT staff working on a ticket, or the commands match a known scheduled script, and nothing else is linked.

## Containment (Tier 2 / IR)

Discovery alone does not need containment. If it is part of a chain, follow the playbook for the most serious linked alert, and treat the user's account and host as compromised.

## Record in the ticket

User, host, commands and timing, whether the user is in IT, linked alerts, and the verdict with reasons.
