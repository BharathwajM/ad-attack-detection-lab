# Playbook: Scheduled task created from the command line

| | |
|---|---|
| **Detection** | [05-scheduled-task.spl](../detections/05-scheduled-task.spl) |
| **ATT&CK** | T1053.005, Scheduled Task/Job: Scheduled Task |
| **Suggested severity** | Medium. Raise to High if the task runs something from a user-writable folder or as SYSTEM. |
| **Data** | Security 4688 (process creation with command line) |

## What the alert means

Someone ran `schtasks /create` or `Register-ScheduledTask`. Attackers use scheduled tasks to keep access after a reboot or to run code as another user. Admins and installers also create tasks all the time, so the command line decides the verdict.

## Lab example

`jsmith` on WS01 created task `ATOMIC-T1053` at 07:37:15, set to run `cmd.exe /c calc.exe` daily at 09:00 ([evidence](../evidence/05-scheduled-task.txt)). The same event shows twice in the results because 4688 stores two account fields, and one of them is `-`.

## Triage steps

1. **Read the full command line.** Note the task name (`/tn`), the action (`/tr`), the schedule (`/sc`), the run-as user (`/ru`) and any remote host (`/s`).
2. **What will the task run?** A signed program in `Program Files` is lower risk. A script or EXE in `Users`, `Temp`, `AppData` or `ProgramData`, or an encoded PowerShell command, is high risk.
3. **Who created it?** Is the user an admin or a normal user? A normal user creating tasks is unusual.
4. **What happened just before?** A task created minutes after a phishing email, a new logon or a discovery burst is part of a chain.
5. **Does the same task exist on other hosts?** The same name on several machines suggests an attacker spreading, or a legitimate rollout.

## Pivot searches

Everything the creator ran on that host (set the time range to about an hour either side):

```spl
index=winlogs source="WinEventLog:Security" EventCode=4688 host="WS01" Account_Name="jsmith"
| table _time Process_Command_Line
```

The same task name on any host:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4688 Process_Command_Line="*ATOMIC-T1053*"
| stats count values(Process_Command_Line) as commands by host
```

Whether the task's action has run:

```spl
index=winlogs source="WinEventLog:Security" EventCode=4688 host="WS01" Process_Command_Line="*calc.exe*"
| table _time Account_Name Process_Command_Line
```

## Likely benign causes

- Software installers and updaters (browsers, backup agents, vendor tools)
- IT scripts or Group Policy deploying maintenance tasks
- An admin creating a task by hand during a change window

## Verdict

**Escalate** if the action runs from a user-writable folder, uses encoded or obfuscated commands, runs as SYSTEM or another user, was created by a non-admin, or other alerts involve the same user or host.

**Close as benign** if the creator, task name and action match a known installer, script or approved change.

## Containment (Tier 2 / IR)

- Export the task (`schtasks /query /tn <name> /xml`) and collect the file it runs before deleting anything.
- Disable and remove the task.
- Check the creator's account and host for other persistence, such as services and Run keys.

## Record in the ticket

Host, creator, task name, action, schedule, run-as user, whether the action has run, related alerts, and the verdict with reasons.
