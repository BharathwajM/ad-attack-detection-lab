# Playbook: Kerberoasting (RC4 service ticket)

| | |
|---|---|
| **Detection** | [01-kerberoasting.spl](../detections/01-kerberoasting.spl) |
| **ATT&CK** | T1558.003, Steal or Forge Kerberos Tickets: Kerberoasting |
| **Suggested severity** | High |
| **Data** | Security 4769 on the domain controller |

## What the alert means

A user asked the DC for a service ticket encrypted with RC4 (`0x17`) for an account that has an SPN. Part of that ticket is encrypted with the service account's password hash, so an attacker can take it away and try to crack the password offline. Modern AD uses AES by default, which is why an RC4 request stands out.

The alert does not mean the password was cracked. It means someone may be trying.

## Lab example

`jsmith` on WS01 (`::ffff:10.10.10.20`) requested 3 RC4 tickets for `svc_sql` between 07:26 and 07:37 ([evidence](../evidence/01-kerberoasting.txt)).

## Triage steps

1. **Who asked, from where?** Note `requestor`, `Client_Address` and the services in `service_accounts`. Map the IP to a hostname.
2. **How many services?** Many SPNs from one user in a short time is typical of tools like Rubeus or `GetUserSPNs.py`. One or two can still be malicious.
3. **Is RC4 expected for this service?** Some old applications only support RC4. Check whether this service account has a known exception.
4. **Is the requester normal for this service?** A SQL admin asking for a SQL ticket is plausible. A finance user asking for it is not.
5. **What else did the requesting account and host do?** Look for discovery commands, spraying or new scheduled tasks around the same time (see the pivots below).
6. **Has the service account logged on anywhere unusual since?** A new logon by the service account from a workstation suggests the password was cracked and is being used.

## Pivot searches

All service tickets for this requester, by service and encryption type:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4769 Account_Name="jsmith*"
| stats count values(Ticket_Encryption_Type) as encryption by Service_Name, Client_Address
```

Where the service account has logged on since:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4624 Account_Name="svc_sql"
| stats count min(_time) as first_seen max(_time) as last_seen values(Source_Network_Address) as src by ComputerName, Logon_Type
| convert ctime(first_seen) ctime(last_seen)
```

What the requester ran on their host:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4688 host="WS01" Account_Name="jsmith"
| table _time host Process_Command_Line
```

## Likely benign causes

- A legacy application or appliance that only supports RC4
- An authorised penetration test or vulnerability scan (check the change calendar)
- A service account with RC4 still enabled in `msDS-SupportedEncryptionTypes`

## Verdict

**Escalate** if the requester has no business need for the service, several SPNs were requested, other alerts involve the same user or host, or the service account logged on from somewhere new.

**Close as benign** only if the requester, host and service match a documented exception, and nothing else is suspicious on the host.

## Containment (Tier 2 / IR)

- Reset the targeted service account's password to a long random value (25+ characters), or move it to a gMSA.
- Set the account to AES only and remove RC4 where possible.
- Treat the requesting account as compromised until proven otherwise: reset its password and review its other activity.

## Record in the ticket

Requester, source IP and hostname, service accounts targeted, ticket count and time range, whether RC4 is expected for the service, related alerts, and the verdict with reasons.
