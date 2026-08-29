# Day 18 — KQL Persistence & Process Correlation Hunting

## 🎯 Objective

Learn how to identify **Windows persistence mechanisms** and correlate them with suspicious process execution.

Today I practiced:

* Registry Run Key hunting
* Scheduled Task hunting
* Windows Service creation
* PowerShell → persistence
* Suspicious persistence paths
* Persistence utility hunting
* Attack-chain reconstruction

```text
Suspicious Process
       ↓
Persistence Mechanism
       ↓
Automatic Execution
       ↓
Repeated Access
```

---

## 1. What is Persistence?

Persistence allows an attacker to maintain access after:

* Reboot
* User logoff
* Process termination
* Security investigation

Common Windows persistence mechanisms:

```text
Registry Run Keys
Scheduled Tasks
Windows Services
Startup Folders
WMI Event Subscriptions
```

> Persistence mechanisms are also heavily used by legitimate software and administrators. The goal is to identify **unexpected or suspicious persistence**, not every persistence event.

---

# 2. Registry Run Key Hunting

Attackers can abuse Registry Run Keys to execute programs automatically when a user logs in.

Common locations:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Run

HKLM\Software\Microsoft\Windows\CurrentVersion\Run
```

A common utility used to modify the registry is:

```text
reg.exe
```

### Mission 1

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "reg.exe"
| where ProcessCommandLine has "CurrentVersion\\Run"
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
```

### Analyst Question

What would make a Run Key modification more suspicious?

```text
Unknown executable
        +
AppData / Temp
        +
PowerShell parent
        +
Unusual account
```

---

# 3. Scheduled Task Persistence

Scheduled Tasks can execute programs based on:

* Logon
* Startup
* Time
* System events

Attackers may abuse:

```text
schtasks.exe
```

### Mission 2

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
```

This searches for scheduled-task creation activity.

---

## Mission 3 — PowerShell + Scheduled Task

A stronger hunting query looks for a PowerShell process creating a scheduled task:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| where InitiatingProcessFileName =~ "powershell.exe"
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
PowerShell
    ↓
schtasks.exe
    ↓
/create
    ↓
Potential Persistence
```

### Correction

The original Mission 3 searched for:

```text
FileName = powershell
```

That would identify PowerShell itself rather than the scheduled-task creation process.

For:

> **"Did PowerShell create a scheduled task?"**

use:

```text
InitiatingProcessFileName = powershell.exe
```

and:

```text
FileName = schtasks.exe
```

---

# 4. Windows Service Persistence

Attackers may create or modify Windows services for persistence or privileged execution.

A common utility is:

```text
sc.exe
```

### Mission 4

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "sc.exe"
| where ProcessCommandLine contains "create"
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
```

This identifies service creation commands executed through `sc.exe`.

---

# 5. Suspicious Service Creation

Now add suspicious paths and interpreters.

### Mission 5

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "sc.exe"
| where ProcessCommandLine contains "create"
| where ProcessCommandLine has_any (
    "powershell",
    "cmd.exe",
    "AppData",
    "Temp",
    "Users\\Public",
    "ProgramData"
)
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
```

### Hunting Logic

```text
sc.exe create
      ↓
Suspicious command/path
      ↓
Potential Service Persistence
```

Again, these indicators require investigation rather than automatic classification.

---

# 6. PowerShell → Scheduled Task

### Mission 6

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "powershell.exe"
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

This is a strong example of **parent-child correlation**.

The query answers:

> **Did PowerShell launch `schtasks.exe` to create a scheduled task?**

---

# 🔥 7. Mini Persistence Hunter

Now combine the persistence mechanisms from today's lesson.

Look for:

```text
reg.exe
schtasks.exe
sc.exe
```

and persistence-related commands:

```text
CurrentVersion\Run
/create
create
```

### Mission 7

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ (
    "reg.exe",
    "schtasks.exe",
    "sc.exe"
)
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
             Persistence Utilities
                     ↓
        ┌────────────┼────────────┐
        ↓            ↓            ↓
     reg.exe    schtasks.exe    sc.exe
        ↓            ↓            ↓
     Run Key       Task         Service
        └────────────┼────────────┘
                     ↓
                Investigation
```

---

# 🧠 Analyst Challenge

Imagine your telemetry shows:

```text
02:15 AM

WINWORD.EXE
      ↓
powershell.exe
      ↓
Invoke-WebRequest
      ↓
update.exe
      ↓
update.exe executed
      ↓
schtasks.exe /create
      ↓
PowerShell
```

Your timeline is now:

```text
Office
 ↓
PowerShell
 ↓
Network
 ↓
File Creation
 ↓
Execution
 ↓
Persistence
```

### Investigation Checklist

Ask:

* Who executed the activity?
* Was the Office → PowerShell relationship expected?
* What URL/IP was contacted?
* What file was downloaded?
* What is the SHA256?
* Where was the file stored?
* What launched `update.exe`?
* What scheduled task was created?
* What was the task name?
* What command/action does the task execute?
* Does the task execute after reboot/logon?
* Which account owns the task?
* Was the same persistence mechanism created on other devices?
* Did the persistence survive a reboot?

---

# 🏆 Bonus — Attack Chain Reconstruction

Try to reconstruct:

```text
Compromised User
       ↓
Malicious Office Document
       ↓
WINWORD.EXE
       ↓
PowerShell
       ↓
External Network Connection
       ↓
Payload Download
       ↓
File Created
       ↓
Payload Executed
       ↓
Scheduled Task Created
       ↓
Persistence
```

### Tables to correlate

```text
DeviceLogonEvents
        ↓
DeviceProcessEvents
        ↓
DeviceNetworkEvents
        ↓
DeviceFileEvents
        ↓
DeviceProcessEvents
```

This is an important transition in your learning.

You are no longer only asking:

> **"Can I find persistence?"**

You are asking:

> **"Can I prove how the persistence fits into the entire attack chain?"**

---

## 📚 KQL Concepts Learned

| KQL / Concept                  | Purpose                             |
| ------------------------------ | ----------------------------------- |
| `reg.exe`                      | Registry modification utility       |
| `CurrentVersion\Run`           | Common Run Key persistence location |
| `schtasks.exe`                 | Scheduled Task management           |
| `/create`                      | Creates a scheduled task            |
| `sc.exe`                       | Windows Service management          |
| `create`                       | Service creation command            |
| `InitiatingProcessFileName`    | Identifies parent process           |
| `InitiatingProcessCommandLine` | Parent command line                 |
| `ProcessCommandLine`           | Command executed by current process |
| `has`                          | Searches for a term                 |
| `has_any()`                    | Searches multiple terms             |
| `in~`                          | Case-insensitive list matching      |
| `summarize`                    | Aggregates events                   |
| `ago()`                        | Relative time filtering             |

---

## 🎯 Day 18 Key Takeaways

1. Persistence allows attackers to maintain access after logoff or reboot.
2. `reg.exe`, `schtasks.exe`, and `sc.exe` can be investigated for persistence activity.
3. Legitimate software also creates scheduled tasks, services, and registry entries.
4. Parent-child relationships can provide important context.
5. `PowerShell → schtasks.exe → /create` is more useful to investigate than simply finding `schtasks.exe`.
6. Suspicious file paths and unusual accounts increase investigation priority.
7. Persistence should be correlated with **authentication, process, network, and file telemetry**.
8. The ultimate goal is to reconstruct the complete attack timeline.

**Day 18 complete. 🛡️**
