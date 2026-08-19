# Day 11 — KQL Persistence Hunting

## 🎯 Objective

Learn how to use KQL to identify **Windows persistence mechanisms** that attackers may abuse to maintain access to a system.

---

## 1. What is Persistence?

**Persistence** is an attacker's ability to maintain access or execution on a system even after:

* Reboot
* User logoff
* Process termination
* Other security actions

Common Windows persistence mechanisms include:

```text
Registry Run Keys
Scheduled Tasks
Windows Services
Startup Folders
WMI Event Subscriptions
```

> Finding a persistence-related command does **not automatically mean compromise**. Legitimate administrators and software can also create tasks, services, and registry entries.

---

## 2. Registry Run Keys

Windows provides Registry locations that can automatically launch programs when a user logs in.

Common locations:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

From process telemetry, useful indicators include:

```text
reg.exe
reg add
CurrentVersion\Run
```

### Mission 1 — Registry Run Key Hunting

```kql
DeviceProcessEvents
| where FileName =~ "reg.exe"
| where ProcessCommandLine contains "CurrentVersion\\Run"
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine
```

---

## 3. Scheduled Task Persistence

Attackers can abuse Windows Scheduled Tasks to execute programs automatically.

A common creation command is:

```text
schtasks.exe /create
```

### Mission 2 — Scheduled Task Creation

```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine
```

### Mission 3 — Scheduled Task → PowerShell

```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| where ProcessCommandLine contains "powershell"
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine
```

This is more interesting because the scheduled task appears to create persistence involving PowerShell.

---

## 4. Windows Service Persistence

Windows Services can also be used for persistence.

A common service-creation command is:

```text
sc.exe create
```

### Mission 4 — Service Creation

```kql
DeviceProcessEvents
| where FileName =~ "sc.exe"
| where ProcessCommandLine contains "create"
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine
```

---

## 5. Suspicious Service Creation

A service creation command deserves additional attention when the configured binary or command references locations or interpreters commonly seen during suspicious activity.

### Mission 5

```kql
DeviceProcessEvents
| where FileName =~ "sc.exe"
| where ProcessCommandLine contains "create"
| where ProcessCommandLine has_any (
    "powershell",
    "cmd.exe",
    "Users\\Public",
    "Temp",
    "AppData"
)
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine
```

> These locations are not inherently malicious. They are investigation signals that should be validated against the organization's normal activity.

---

## 6. PowerShell → Scheduled Task

Now combine **Day 10 parent-child hunting** with today's persistence hunting.

We want to identify:

```text
PowerShell
     ↓
schtasks.exe
     ↓
/create
```

### Mission 6

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

This is more useful than simply finding `schtasks.exe` because we can see **which process launched it**.

---

## 🔥 Mission 7 — Persistence Hunter

Combine Registry Run Keys, Scheduled Tasks, and Service creation into one hunting query.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("reg.exe", "schtasks.exe", "sc.exe")
| where ProcessCommandLine has_any (
    "CurrentVersion\\Run",
    "/create",
    "create"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

### Hunting Logic

```text
                 Persistence
                     |
        +------------+------------+
        |            |            |
     Registry    Scheduled      Service
       Run          Task         Create
        |            |            |
      reg.exe     schtasks.exe    sc.exe
```

---

# 🧠 Analyst Challenge

Suppose you find:

```text
02:20 AM
     |
powershell.exe
     |
schtasks.exe /create
     |
Task: WindowsUpdate
     |
PowerShell script
```

This is **suspicious enough to investigate**, especially if it is unusual for the device or user.

However, it should not be declared malicious based only on this query.

### Investigation Checklist

I would check:

* **Task name** — Is the name trying to imitate a legitimate Windows task?
* **Task action** — What executable or script does it launch?
* **Script path** — Is it located in an unusual directory?
* **User** — Who created the task?
* **Parent process** — What launched `schtasks.exe`?
* **Command line** — What arguments were used?
* **File hash** — Is the executable/script known or suspicious?
* **Network connections** — Did the process communicate externally?
* **Registry changes** — Was additional persistence created?
* **Previous activity** — What happened before the task was created?
* **Task history** — Did this task already exist or was it newly created?

---

## 🎯 Day 11 Key Takeaways

1. Persistence allows attackers to maintain execution/access after events such as reboot or logoff.
2. Registry Run Keys can automatically execute programs during user logon.
3. `schtasks.exe /create` can create scheduled tasks.
4. `sc.exe create` can create Windows services.
5. Parent-child relationships can reveal how persistence was established.
6. Unusual paths such as `Temp`, `AppData`, or `Users\Public` deserve additional investigation when combined with suspicious execution.
7. Persistence indicators are **investigation leads**, not automatic proof of compromise.

### Today's Hunting Mindset

```text
Day 10
"What launched the process?"
        ↓
Day 11
"Did the process create persistence?"
        ↓
Next
"Who created it, what will execute,
and when will it execute?"
```

---

## 📚 KQL Concepts Practiced

| KQL                         | Purpose                                           |
| --------------------------- | ------------------------------------------------- |
| `where`                     | Filter events                                     |
| `=~`                        | Case-insensitive equality                         |
| `in~`                       | Case-insensitive matching against multiple values |
| `contains`                  | Search within a string                            |
| `has_any()`                 | Search for multiple terms                         |
| `ago()`                     | Search recent activity                            |
| `project`                   | Select investigation fields                       |
| `InitiatingProcessFileName` | Identify the initiating process                   |
| `ProcessCommandLine`        | Investigate execution details                     |
