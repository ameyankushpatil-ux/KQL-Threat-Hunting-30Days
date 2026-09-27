Your Day 22 work is solid. I corrected the final multi-table query so it actually **projects the logon and file fields**, and cleaned up the formatting and explanations for a professional GitHub report.

# 🟢 Day 22 — KQL Mission: Joins & Cross-Table Correlation

**⏱️ Time:** 30 Minutes
**🎯 Level:** Advanced Threat Hunting → Detection Engineering
**📌 Focus:** `join`, `let`, Cross-Table Correlation, Time Windows & Attack Chains

---

## 🎯 Objective

A real SOC investigation rarely relies on a single telemetry source.

For example:

```text
PowerShell execution
       ↓
Network connection
       ↓
File creation
       ↓
Logon activity
```

KQL's `join` operator allows us to correlate these events across different Defender Advanced Hunting tables.

### Key Concepts

* `join` → combines data from multiple tables
* `inner` → returns matching records
* `leftouter` → keeps all records from the left dataset
* `let` → creates reusable query datasets
* `bin()` → creates time windows
* `DeviceId` → useful device correlation key

---

# 🔎 Mission 1 — PowerShell + Network Correlation

### Objective

Find PowerShell execution and network activity occurring on the same device within a 5-minute window.

```kql
let PowerShellActivity =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
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
              InitiatingProcessFileName,
              TimeWindow;

PowerShellActivity
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

### What did we learn?

Instead of looking at PowerShell alone, we can now ask:

> **Did PowerShell activity coincide with network communication?**

---

# 🔎 Mission 2 — PowerShell + Network Ports

Now focus on common web-related ports.

```kql
let PowerShellActivity =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
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
    | where RemotePort in (80, 443, 8080, 8443)
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              NetworkTime = Timestamp,
              RemoteIP,
              RemotePort,
              RemoteUrl,
              TimeWindow;

PowerShellActivity
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

### Analyst Thinking

A connection to port `443` is **not automatically malicious**.

The important question is:

> **Why did this particular PowerShell process communicate with that destination?**

Always investigate the surrounding context.

---

# 🔎 Mission 3 — PowerShell + File Creation

Correlate PowerShell execution with files created around the same time.

```kql
let PowerShellActivity =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
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
              InitiatingProcessAccountName,
              TimeWindow;

PowerShellActivity
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

### Investigation Flow

```text
PowerShell
    ↓
File Created
    ↓
What file?
    ↓
Where was it created?
    ↓
What is the SHA256?
    ↓
Is the file expected?
```

---

# 🔎 Mission 4 — Logon + PowerShell

Correlate successful logons with PowerShell execution.

```kql
let LogonActivity =
    DeviceLogonEvents
    | where Timestamp > ago(24h)
    | where ActionType == "LogonSuccess"
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              LogonTime = Timestamp,
              AccountName,
              LogonType,
              RemoteIP,
              TimeWindow;

let PowerShellActivity =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              DeviceName,
              ProcessTime = Timestamp,
              AccountName,
              ProcessCommandLine,
              TimeWindow;

LogonActivity
| join kind=inner PowerShellActivity on DeviceId, TimeWindow
| project LogonTime,
          ProcessTime,
          DeviceName,
          AccountName,
          LogonType,
          RemoteIP,
          ProcessCommandLine
| order by ProcessTime desc
```

### Analyst Questions

* Which account logged in?
* Was the logon remote?
* What happened immediately afterward?
* Was PowerShell expected for this account?

---

# 🔎 Mission 5 — Understanding `leftouter`

Not every PowerShell event will have a matching network event.

`leftouter` allows us to keep the PowerShell event even when no matching network activity exists.

```kql
let PowerShellActivity =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
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

PowerShellActivity
| join kind=leftouter NetworkActivity on DeviceId, TimeWindow
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

### Difference

```text
inner
  ↓
Only matching records

leftouter
  ↓
Keep all records from the left side
even when no match exists
```

---

# 🚨 Mission 6 — Multi-Table Attack-Chain Correlation

Now combine:

* Logon
* PowerShell
* Network
* File creation

```kql
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

let PowerShellActivity =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where FileName =~ "powershell.exe"
    | extend TimeWindow = bin(Timestamp, 5m)
    | project DeviceId,
              DeviceName,
              ProcessTime = Timestamp,
              ProcessAccount = AccountName,
              ProcessCommandLine,
              TimeWindow;

let NetworkActivity =
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where RemotePort in (80, 443, 8080, 8443)
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
              InitiatingProcessFileName,
              TimeWindow;

PowerShellActivity
| join kind=leftouter NetworkActivity on DeviceId, TimeWindow
| join kind=leftouter FileActivity on DeviceId, TimeWindow
| join kind=leftouter LogonActivity on DeviceId, TimeWindow
| project ProcessTime,
          DeviceName,
          ProcessAccount,
          ProcessCommandLine,
          LogonTime,
          LogonAccount,
          LogonType,
          LogonRemoteIP,
          NetworkTime,
          RemoteIP,
          RemotePort,
          RemoteUrl,
          FileTime,
          FileName,
          FolderPath,
          SHA256,
          InitiatingProcessFileName
| order by ProcessTime desc
```

### Attack-Chain View

```text
Remote Logon
     ↓
PowerShell Execution
     ↓
Network Connection
     ↓
File Creation
     ↓
Investigation
```

This is much closer to how a real SOC analyst reconstructs an incident.

---

# 🧠 Analyst Challenge

You discover:

```text
08:41 → Remote logon
08:43 → PowerShell executed
08:44 → External network connection
08:45 → New executable created
```

### Questions

1. Which account performed the activity?
2. Which device was involved?
3. What was the PowerShell command line?
4. What remote IP/domain was contacted?
5. What file was created?
6. What was the SHA256?
7. Was the activity expected?
8. What additional evidence would you investigate?

### Build the Story

```text
Logon
  ↓
Process
  ↓
Network
  ↓
File
  ↓
Investigation
```

The objective is **not** to immediately declare the activity malicious.

The objective is to correlate evidence and provide enough context for an analyst to make a reliable determination.

---

# 📌 Key Takeaways

* `join` allows cross-table threat hunting.
* `let` makes complex queries easier to build and maintain.
* `DeviceId` provides a useful correlation key.
* `bin(Timestamp, 5m)` creates a practical time window.
* `inner` returns matching events.
* `leftouter` preserves the primary dataset even without a match.
* Process + Network + File + Logon provides much richer investigation context.
* Correlation creates an **investigation lead**, not automatic proof of compromise.

ps your original six missions, but Mission 6 is now materially better because the final output includes the **logon, network, and file evidence** instead of accidentally projecting `ProcessCommandLine` twice.
