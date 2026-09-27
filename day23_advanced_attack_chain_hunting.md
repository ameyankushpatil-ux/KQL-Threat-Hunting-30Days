Day 23 will build directly on Day 22. You'll move from simply joining events to **reconstructing multi-stage attack chains** and identifying when several weak signals combine into a stronger investigation lead.

# 🟢 Day 23 — KQL Mission: Advanced Attack-Chain Hunting

**⏱️ Time:** 30 Minutes
**🎯 Level:** Advanced Threat Hunting → Detection Engineering
**📌 Focus:** Attack Chains, Multi-Stage Correlation, `join`, `let`, Time Windows & Risk Context

---

## 🎯 Objective

On Day 22, we learned how to correlate events across multiple Defender tables.

Today we take the next step:

> **Can we reconstruct a suspicious sequence of activities instead of investigating individual events?**

A real attack may generate many separate telemetry events:

```text
Remote Logon
     ↓
Office / Script Interpreter
     ↓
PowerShell
     ↓
Network Connection
     ↓
File Creation
     ↓
Persistence
```

No single event necessarily proves malicious activity.

The **sequence and context** can make the investigation more meaningful.

---

# 🧠 Mission 1 — Identify Suspicious PowerShell

Start with PowerShell containing suspicious command-line indicators.

```kql id="0e5b2q"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX",
    "FromBase64String"
)
| project Timestamp,
          DeviceId,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          ProcessCommandLine
| order by Timestamp desc
```

### Analyst Question

Don't immediately label the event malicious.

Ask:

* Who executed it?
* From which device?
* What was the parent process?
* What exactly was executed?

---

# 🔎 Mission 2 — PowerShell → Network

Now correlate suspicious PowerShell with network activity.

```kql id="n8c1s4"
let SuspiciousPowerShell =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX",
        "FromBase64String"
    )
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              DeviceName,
              AccountName,
              ProcessTime = Timestamp,
              ProcessCommandLine,
              TimeWindow;

let NetworkActivity =
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              NetworkTime = Timestamp,
              RemoteIP,
              RemotePort,
              RemoteUrl,
              TimeWindow;

SuspiciousPowerShell
| join kind=inner NetworkActivity on DeviceId, TimeWindow
| project ProcessTime,
          NetworkTime,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          RemoteIP,
          RemotePort,
          RemoteUrl
| order by ProcessTime desc
```

### Attack Stage

```text
Suspicious PowerShell
        ↓
Network Communication
```

---

# 🔎 Mission 3 — PowerShell → File Creation

Now determine whether the activity was followed by file creation.

```kql id="o3z9f6"
let SuspiciousPowerShell =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX",
        "FromBase64String"
    )
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              DeviceName,
              AccountName,
              ProcessTime = Timestamp,
              ProcessCommandLine,
              TimeWindow;

let FileActivity =
    DeviceFileEvents
    | where Timestamp > ago(24h)
    | where ActionType == "FileCreated"
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              FileTime = Timestamp,
              FileName,
              FolderPath,
              SHA256,
              InitiatingProcessFileName,
              TimeWindow;

SuspiciousPowerShell
| join kind=inner FileActivity on DeviceId, TimeWindow
| project ProcessTime,
          FileTime,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          FileName,
          FolderPath,
          SHA256,
          InitiatingProcessFileName
| order by ProcessTime desc
```

### Attack Stage

```text
Suspicious PowerShell
        ↓
File Creation
```

---

# 🔎 Mission 4 — Office → PowerShell → Network

Now investigate a complete execution chain.

```kql id="jj2q7x"
let OfficePowerShell =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where InitiatingProcessFileName in~ (
        "WINWORD.EXE",
        "EXCEL.EXE",
        "OUTLOOK.EXE"
    )
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX"
    )
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              DeviceName,
              AccountName,
              ProcessTime = Timestamp,
              OfficeProcess = InitiatingProcessFileName,
              ProcessCommandLine,
              TimeWindow;

let NetworkActivity =
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              NetworkTime = Timestamp,
              RemoteIP,
              RemotePort,
              RemoteUrl,
              TimeWindow;

OfficePowerShell
| join kind=inner NetworkActivity on DeviceId, TimeWindow
| project ProcessTime,
          NetworkTime,
          DeviceName,
          AccountName,
          OfficeProcess,
          ProcessCommandLine,
          RemoteIP,
          RemotePort,
          RemoteUrl
| order by ProcessTime desc
```

### Chain

```text
Office
  ↓
PowerShell
  ↓
Suspicious Command
  ↓
Network
```

This provides substantially more context than detecting PowerShell by itself.

---

# 🔎 Mission 5 — Build a Three-Stage Correlation

Now combine:

```text
PowerShell
    ↓
Network
    ↓
File Creation
```

```kql id="e0h4kh"
let PowerShellActivity =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX"
    )
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              DeviceName,
              AccountName,
              ProcessTime = Timestamp,
              ProcessCommandLine,
              TimeWindow;

let NetworkActivity =
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              NetworkTime = Timestamp,
              RemoteIP,
              RemotePort,
              RemoteUrl,
              TimeWindow;

let FileActivity =
    DeviceFileEvents
    | where Timestamp > ago(24h)
    | where ActionType == "FileCreated"
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              FileTime = Timestamp,
              FileName,
              FolderPath,
              SHA256,
              TimeWindow;

PowerShellActivity
| join kind=inner NetworkActivity on DeviceId, TimeWindow
| join kind=inner FileActivity on DeviceId, TimeWindow
| project ProcessTime,
          NetworkTime,
          FileTime,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          RemoteIP,
          RemotePort,
          RemoteUrl,
          FileName,
          FolderPath,
          SHA256
| order by ProcessTime desc
```

### Resulting Attack Chain

```text
PowerShell
    ↓
Network
    ↓
File Creation
```

---

# 🚨 Mission 6 — Add Logon Context

Now add the identity dimension.

```kql id="1tr5s5"
let LogonActivity =
    DeviceLogonEvents
    | where Timestamp > ago(24h)
    | where ActionType == "LogonSuccess"
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              LogonTime = Timestamp,
              LogonAccount = AccountName,
              LogonType,
              LogonRemoteIP = RemoteIP,
              TimeWindow;

let SuspiciousPowerShell =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX"
    )
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              DeviceName,
              ProcessTime = Timestamp,
              ProcessAccount = AccountName,
              ProcessCommandLine,
              TimeWindow;

LogonActivity
| join kind=inner SuspiciousPowerShell on DeviceId, TimeWindow
| project LogonTime,
          ProcessTime,
          DeviceName,
          LogonAccount,
          LogonType,
          LogonRemoteIP,
          ProcessAccount,
          ProcessCommandLine
| order by ProcessTime desc
```

### Why is identity important?

The same PowerShell command can have very different context depending on:

* Which account executed it
* Whether the account normally uses PowerShell
* Whether the account recently logged in remotely
* Whether the device belongs to that user

---

# 🧪 Analyst Challenge — Reconstruct the Incident

You discover:

```text
08:41 → Remote logon
08:43 → Office application launches PowerShell
08:43 → Encoded PowerShell command
08:44 → External network connection
08:45 → Executable created
```

### Your Investigation

Determine:

**WHO?**

```text
Account
```

**WHERE?**

```text
Device
```

**HOW?**

```text
Parent Process
```

**WHAT?**

```text
PowerShell Command
```

**WHERE DID IT CONNECT?**

```text
RemoteIP / RemoteUrl
```

**WHAT WAS CREATED?**

```text
FileName / FolderPath
```

**WHAT IS THE FILE?**

```text
SHA256
```

**WHAT HAPPENED BEFORE AND AFTER?**

```text
Logon
  ↓
Execution
  ↓
Network
  ↓
File
  ↓
Persistence / Additional Activity
```

---

# 🧠 Detection Engineering Challenge

Suppose you have these individual detections:

```text
Detection A → Remote Logon
Detection B → PowerShell
Detection C → Encoded Command
Detection D → Network Connection
Detection E → File Creation
```

Individually, each detection may generate noise.

But when several occur together:

```text
A + B + C + D + E
```

the investigation priority may increase.

### Important

This does **not** mean:

> Five alerts = confirmed attack.

It means:

> **Multiple related signals provide stronger context for investigation.**

---

# 📌 Key Takeaways

* Attackers generate sequences of events, not just individual events.
* Cross-table correlation helps reconstruct those sequences.
* `join` can connect process, network, file and logon telemetry.
* Time windows help associate events occurring close together.
* Identity and device context are critical.
* Multiple weak signals can create a stronger investigation lead.
* Correlation should improve analyst context rather than automatically declare an incident malicious.
