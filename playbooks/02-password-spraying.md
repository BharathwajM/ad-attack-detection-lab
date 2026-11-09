# Playbook: Password spraying

| | |
|---|---|
| **Detection** | [02-password-spraying.spl](../detections/02-password-spraying.spl) |
| **ATT&CK** | T1110.003, Brute Force: Password Spraying |
| **Suggested severity** | Medium. Raise to High if any targeted account logs on successfully afterwards. |
| **Data** | Security 4625 (failed logon) |

## What the alert means

One source failed to log on to 5 or more different accounts within 10 minutes. Spraying tries one or two common passwords across many accounts, staying under the lockout threshold. That is different from brute force, which hammers one account.

The real question is whether any of the guesses worked.

## Lab example

37 failed logons against 5 account names (Administrator, jsmith, labadmin in two formats, and WS01$) in the 07:10 window, reported from workstation WS01 ([evidence](../evidence/02-password-spraying.txt)). `Source_Network_Address` was empty (`-`), so `Workstation_Name` was the field to pivot on.

## Triage steps

1. **Where did it come from?** Use `Source_Network_Address`, or `Workstation_Name` when the address is empty. Is the source internal, a VPN range, or the internet?
2. **Read the failure codes in `Sub_Status`.**
   - `0xC000006A`: right username, wrong password. The attacker knows real account names.
   - `0xC0000064`: the username does not exist. The attacker is guessing names.
   - `0xC0000234`: the account is locked out. Users will start calling the service desk.
3. **Did any targeted account log on successfully** from the same source during or after the spray? This decides the severity.
4. **Which accounts were targeted?** Privileged or service accounts in the list raise the priority.
5. **Is the source host doing anything else?** Check for other alerts on the same host.

## Pivot searches

Failure codes per account:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4625 Workstation_Name="WS01"
| stats count by Account_Name, Sub_Status
```

Successful logons from the same workstation (the most important check):

```spl
index=winlogs source="WinEventLog:Security" EventCode=4624 Workstation_Name="WS01"
| eval target=mvindex(Account_Name, -1)
| stats count min(_time) as first_seen max(_time) as last_seen by target, ComputerName, Logon_Type
| convert ctime(first_seen) ctime(last_seen)
```

Lockouts caused by the spray:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4625 Sub_Status="0xC0000234"
| stats count by Account_Name, Workstation_Name, Source_Network_Address
```

## Likely benign causes

- A service or scheduled job still using an old password after a password change, which fails across several accounts at once
- A misconfigured application or monitoring tool cycling through stored credentials
- A user typing the wrong username format several times (usually one or two accounts, not five)

## Verdict

**Escalate** if any targeted account logged on successfully from the source, privileged accounts were targeted, the source is external or unknown, or other alerts involve the same host.

**Close as benign** if the source is a known server with an expired stored credential, and no logon succeeded. Raise a ticket to fix the stored credential.

## Containment (Tier 2 / IR)

- Block or isolate the source host.
- Reset the password of any account that logged on successfully, and review what it did.
- Unlock locked accounts only after confirming the users.
- Check that MFA is enforced for the targeted accounts.

## Record in the ticket

Source IP or workstation, accounts targeted, failure codes, whether any logon succeeded, lockouts caused, related alerts, and the verdict with reasons.
