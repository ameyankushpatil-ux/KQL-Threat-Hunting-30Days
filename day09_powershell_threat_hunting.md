# Day 09 — PowerShell Threat Hunting

## 🎯 Objective

Use KQL to investigate PowerShell activity and identify command-line behaviors that may require further investigation.

Today I practiced:

* PowerShell process hunting
* Encoded PowerShell
* Execution Policy Bypass
* PowerShell downloads
* Obfuscation indicators
* Suspicious PowerShell command lines
* Office → PowerShell process relationships

---

## 🧪 Mission 1 — PowerShell Activity

Find PowerShell executions and display the main investigation fields.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

---

## 🧪 Mission 2 — Encoded PowerShell

Search for PowerShell commands containing `-enc` or `EncodedCommand` during the last 24 hours.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "EncodedCommand")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Learning

Encoded commands can be used to hide PowerShell instructions. However, the presence of `-enc` alone does not prove malicious activity.

---

## 🧪 Mission 3 — Execution Policy Bypass

The objective is to identify PowerShell commands containing both `ExecutionPolicy` and `Bypass`.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_all ("ExecutionPolicy", "Bypass")
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Correction

`has_any()` was changed to `has_all()` because both terms are required for this hunting condition.

---

## 🧪 Mission 4 — PowerShell Download Activity

Search for PowerShell commands that may download content.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "DownloadString",
    "DownloadFile",
    "Invoke-WebRequest",
    "iwr",
    "Net.WebClient"
)
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Investigation Focus

If a suspicious download is found, investigate:

* Destination URL/IP
* Downloaded file
* File hash
* Parent process
* User
* Subsequent process execution

---

## 🧪 Mission 5 — PowerShell Obfuscation

Search for common indicators associated with encoded or obfuscated PowerShell.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "FromBase64String",
    "IEX",
    "Invoke-Expression"
)
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

---

## 🔥 Mission 6 — PowerShell Hunter

Combine multiple suspicious PowerShell indicators into one hunting query.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "-enc",
    "ExecutionPolicy",
    "DownloadString",
    "DownloadFile",
    "Invoke-WebRequest",
    "IEX",
    "FromBase64String"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Hunting Logic

```text
PowerShell
    ↓
Last 24 hours
    ↓
Suspicious command-line indicator
    ↓
Relevant investigation fields
    ↓
Analyst investigation
```

---

## 🧪 Mission 7 — Office → Encoded PowerShell

Investigate PowerShell launched by Microsoft Word where the command contains an encoded-command indicator.

```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "WINWORD.EXE"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "EncodedCommand"
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

### Why is this more interesting?

Finding:

```text
powershell.exe
```

alone provides limited context.

Finding:

```text
WINWORD.EXE
      ↓
powershell.exe
      ↓
EncodedCommand
```

provides a much stronger investigation lead because we now have:

* A parent/child process relationship
* PowerShell execution
* Suspicious command-line behavior

It still requires investigation before declaring the activity malicious.

---

# 🧠 SOC Analyst Investigation

When suspicious PowerShell is identified, investigate:

1. **Parent process** — What launched PowerShell?
2. **Command line** — What exactly was executed?
3. **User** — Who initiated the activity?
4. **Device history** — Is this normal for the endpoint?
5. **Network activity** — Did PowerShell communicate externally?
6. **Files/scripts** — Was a suspicious file created or executed?
7. **Persistence** — Were registry keys, scheduled tasks, or services modified?
8. **Follow-up activity** — What happened immediately after PowerShell execution?

---

## ⚠️ Important Lesson

A PowerShell indicator does **not automatically mean malware**.

For example:

```text
ExecutionPolicy
EncodedCommand
DownloadString
IEX
```

can appear in legitimate administration, automation, deployment, or security tools.

Therefore:

> **Indicators create investigation leads; context determines whether the activity is malicious.**

---

## 📚 KQL Concepts Learned

| Concept                     | Purpose                               |
| --------------------------- | ------------------------------------- |
| `=~`                        | Case-insensitive equality             |
| `has_any()`                 | Matches any term from a list          |
| `has_all()`                 | Requires all specified terms          |
| `ago()`                     | Searches a relative time period       |
| `InitiatingProcessFileName` | Identifies the initiating process     |
| `ProcessCommandLine`        | Shows the executed command            |
| `project`                   | Selects relevant investigation fields |

---

## 🎯 Day 09 Key Takeaway

My hunting approach is changing from:

> **"Find PowerShell."**

to:

> **"Find PowerShell with suspicious behavior, understand how it was launched, and investigate what happened before and after execution."**

This is the foundation of **PowerShell threat hunting and behavioral detection engineering**.

---

## 📁 GitHub

**File:**

```text
day09_powershell_threat_hunting.md
```

**Commit:**

```text
Day 09: PowerShell threat hunting
```

### Progress

```text
Day 01 ✅ KQL Basics
Day 02 ✅ Filtering
Day 03 ✅ String Hunting
Day 04 ✅ Calculated Fields
Day 05 ✅ Aggregation
Day 06 ✅ Time-Based Hunting
Day 07 ✅ Advanced Filtering
Day 08 ✅ Windows Process Hunting
Day 09 ✅ PowerShell Threat Hunting
```

**Day 09 complete. ✅**
