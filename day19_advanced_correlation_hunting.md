# Day 19 — KQL Advanced Correlation & Behavioral Hunting

## 🎯 Objective

Learn how to correlate multiple telemetry signals instead of investigating individual events in isolation.

Today I practiced:

* Process → Network correlation
* Suspicious PowerShell + Network
* Process → File correlation
* Suspicious location + execution
* PowerShell → Scheduled Task
* Account + Device + Process + Destination analysis
* Office → PowerShell behavioral hunting

---

## 1. What is Correlation?

A single event may be completely legitimate.

For example:

```text
powershell.exe
```

does **not** automatically mean malware.

But:

```text
WINWORD.EXE
     ↓
PowerShell
     ↓
EncodedCommand
     ↓
Network Connection
     ↓
File Creation
     ↓
Scheduled Task
```

is much more interesting.

The goal of correlation is:

```text
Weak Signal
    +
Weak Signal
    +
Weak Signal
    ↓
Stronger Investigation Lead
```

> Correlation increases confidence, but it does not automatically prove malicious activity.

---

# 2. Process → Network Correlation

Start with suspicious processes making network connections.

### Mission 1

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "powershell.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "certutil.exe"
)
| project Timestamp,
          DeviceName,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          RemoteIP,
          RemotePort,
          RemoteUrl
```

This connects:

```text
Process
   ↓
Network
   ↓
Destination
```

### Analyst Question

Which combination is more interesting?

```text
PowerShell → Unknown External IP
```

or:

```text
PowerShell → Known Microsoft Service
```

The unknown external destination deserves more investigation because the destination may be unexpected for that endpoint or process.

However:

> An external IP is not automatically malicious. Validate ownership, reputation, URL, timing, process context, and user behavior.

### Correction

The original query used:

```text
Account
Process
CommandLine
```

The appropriate `DeviceNetworkEvents` fields are:

```text
InitiatingProcessAccountName
InitiatingProcessFileName
InitiatingProcessCommandLine
```

---

# 3. Suspicious Command + Network

Now increase the signal by looking for suspicious PowerShell indicators.

### Mission 2

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "powershell.exe"
| where InitiatingProcessCommandLine has_any (
    "EncodedCommand",
    "ExecutionPolicy",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX",
    "FromBase64String"
)
| project Timestamp,
          DeviceName,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          RemoteIP,
          RemotePort,
          RemoteUrl
```

### Hunting Logic

```text
PowerShell
    ↓
Suspicious Command
    ↓
Network Connection
    ↓
Potential Download / C2
```

---

# 4. Process → File Correlation

Now combine Day 16 and Day 17.

### Mission 3

The goal is to identify file activity associated with suspicious interpreters.

```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "powershell.exe",
    "cmd.exe",
    "mshta.exe",
    "wscript.exe",
    "cscript.exe"
)
| project Timestamp,
          DeviceName,
          InitiatingProcessAccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          FolderPath,
          SHA256
```

### Hunting Logic

```text
Suspicious Process
       ↓
File Activity
       ↓
File Path
       ↓
SHA256
       ↓
Investigation
```

### Correction

The original Mission 3 used `DeviceNetworkEvents` but attempted to display:

```text
FileName
FolderPath
SHA256
```

Those fields belong to file/process telemetry, so `DeviceFileEvents` is the appropriate table here.

---

# 5. Suspicious File + Execution

### Mission 4

Investigate a suspicious executable:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "update.exe"
| where FolderPath has "C:\\Users\\Public\\"
| where InitiatingProcessFileName =~ "powershell.exe"
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          FolderPath,
          ProcessCommandLine,
          SHA256
```

This answers:

> **Was `update.exe` executed from `Users\Public` by PowerShell?**

This is stronger than simply searching for the filename.

---

# 6. PowerShell → Scheduled Task

Day 18 introduced persistence.

Now correlate it with PowerShell.

### Mission 5

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

This is a good example of **parent-child behavioral correlation**.

---

# 7. Account + Process + Network

Now bring Day 12 back into the investigation.

### Mission 6

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "powershell.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "certutil.exe"
)
| summarize Count = count()
    by InitiatingProcessAccountName,
       DeviceName,
       InitiatingProcessFileName,
       RemoteIP
| order by Count desc
```

This helps identify:

> **Which accounts and devices are generating network connections through suspicious or commonly abused processes?**

### Analyst Warning

A high count does not automatically indicate compromise.

For example:

```text
svc_backup → PowerShell → 500 connections
```

may be completely legitimate if that service account is used for automation.

Always compare against:

* Normal behavior
* Account role
* Device role
* Destination
* Time
* Command line

---

# 🔥 8. Office → Script Interpreter → Suspicious Command

This is your first strong behavioral hunting query.

### Mission 7

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE",
    "EXCEL.EXE",
    "OUTLOOK.EXE"
)
| where FileName in~ (
    "powershell.exe",
    "mshta.exe",
    "cmd.exe"
)
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "DownloadString",
    "Invoke-WebRequest",
    "ExecutionPolicy",
    "IEX"
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
Office Application
       ↓
Script Interpreter
       ↓
Suspicious Command
       ↓
Investigate Network + File + Persistence
```

This is much closer to a real **behavior-based hunting query**.

---

# 🧠 Analyst Challenge

You discover:

```text
02:15 AM

Account: john

PC-02
  ↓
WINWORD.EXE
  ↓
PowerShell
  ↓
EncodedCommand
  ↓
Invoke-WebRequest
  ↓
External IP
  ↓
update.exe
  ↓
Scheduled Task
```

You now have:

```text
Authentication
       ↓
Lateral Movement
       ↓
Office Execution
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

## Would I call this malicious immediately?

**I would treat it as a high-priority suspicious activity chain, but still validate the evidence before making the final determination.**

### Investigation Checklist

* Is `john` expected to perform this activity?
* Is the Office document legitimate?
* What is the complete PowerShell command?
* Can the encoded command be safely decoded?
* What destination did PowerShell contact?
* Is the destination known or expected?
* What is the downloaded file's SHA256?
* Where was `update.exe` stored?
* Did `update.exe` actually execute?
* What child processes did it launch?
* What scheduled task was created?
* What command/action does the task execute?
* Does the same hash appear on other endpoints?
* Did the same attack pattern occur elsewhere?

---

# 🏆 Bonus — Attack Chain Reconstruction

Your goal is now to connect multiple telemetry sources:

```text
Compromised User
       ↓
Remote Authentication
       ↓
Lateral Movement
       ↓
WINWORD.EXE
       ↓
PowerShell
       ↓
Suspicious Command
       ↓
Network Connection
       ↓
Payload Download
       ↓
File Creation
       ↓
Payload Execution
       ↓
Scheduled Task
       ↓
Persistence
```

Relevant tables:

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

### Detection Engineering Mindset

Instead of creating separate alerts for:

```text
PowerShell
```

```text
Network Connection
```

```text
File Creation
```

```text
Scheduled Task
```

think about the **relationship between them**:

```text
Office
  ↓
PowerShell
  ↓
Suspicious Command
  ↓
Network
  ↓
File
  ↓
Execution
  ↓
Persistence
```

The more independent signals that support the same attack story, the higher the investigation priority can become.

---

# 📚 KQL Concepts Learned

| Concept                        | Purpose                                    |
| ------------------------------ | ------------------------------------------ |
| Correlation                    | Connect multiple security events           |
| `DeviceProcessEvents`          | Process execution                          |
| `DeviceNetworkEvents`          | Network activity                           |
| `DeviceFileEvents`             | File activity                              |
| `InitiatingProcessFileName`    | Parent/initiating process                  |
| `InitiatingProcessCommandLine` | Parent command line                        |
| `ProcessCommandLine`           | Current process command line               |
| `InitiatingProcessAccountName` | Account associated with initiating process |
| `in~`                          | Case-insensitive list matching             |
| `has_any()`                    | Search multiple indicators                 |
| `summarize`                    | Aggregate events                           |
| `count()`                      | Count events                               |
| `order by`                     | Sort results                               |
| Behavioral hunting             | Detect combinations of activity            |

---

# 🎯 Day 19 Key Takeaways

1. A single event rarely provides enough context.
2. Correlation combines multiple signals into a stronger investigation lead.
3. **Process + Network** is more informative than process alone.
4. **Process + File** helps identify potential payload activity.
5. **Process + Persistence** can reveal an attempt to maintain access.
6. Account and device context are essential for reducing false positives.
7. Office → PowerShell → Network → File → Persistence is a valuable attack-chain pattern to investigate.
8. Good threat hunting focuses on **relationships and behavior**, not only individual IOCs.
9. Strong correlation improves the foundation for future **detection engineering**.

**Day 19 complete. 🛡️**
