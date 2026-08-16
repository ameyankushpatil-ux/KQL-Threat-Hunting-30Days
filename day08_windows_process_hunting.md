# Day 08 — Windows Process Hunting

## 🎯 Objective

Start applying KQL to real SOC-style process hunting.

Today I learned:

* `DeviceProcessEvents`
* Process execution hunting
* LOLBins
* `ProcessCommandLine`
* Parent/initiating process analysis
* Office → PowerShell process chains
* Office → LOLBin process chains

---

## 1. Process Inventory

`DeviceProcessEvents` contains endpoint process execution telemetry.

### Mission 1

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Purpose

This provides a basic view of process activity from the last 24 hours.

---

## 2. LOLBin Hunting

**LOLBin = Living-off-the-Land Binary**

These are legitimate Windows utilities that can also be abused by attackers.

Examples:

```text
powershell.exe
cmd.exe
mshta.exe
rundll32.exe
regsvr32.exe
wscript.exe
cscript.exe
certutil.exe
```

### Important

A LOLBin is **not inherently malicious**.

For example, PowerShell is a legitimate Windows administration tool.

The **context and behavior** determine whether the activity is suspicious.

### Mission 2

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ (
    "powershell.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "wscript.exe",
    "cscript.exe",
    "certutil.exe"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Correction

The original query used:

```text
ProcessName
```

For this `DeviceProcessEvents` hunting scenario, use:

```text
FileName
```

to identify the process.

---

## 3. Suspicious PowerShell

Finding PowerShell alone is not enough. We should investigate what PowerShell executed.

### Mission 3

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "ExecutionPolicy",
    "DownloadString",
    "IEX",
    "Invoke-WebRequest"
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Hunting logic

```text
Recent activity
      ↓
PowerShell
      ↓
Suspicious command-line indicators
      ↓
Investigation
```

---

## 4. Office → PowerShell

A useful process relationship to investigate is:

```text
WINWORD.EXE
      ↓
powershell.exe
```

or:

```text
OUTLOOK.EXE
      ↓
powershell.exe
```

These relationships are not automatically malicious, but they can deserve investigation.

### Mission 4

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "outlook.exe"
)
| where FileName =~ "powershell.exe"
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessCommandLine
```

### Important fields

| Field                          | Purpose                                |
| ------------------------------ | -------------------------------------- |
| `InitiatingProcessFileName`    | Process that initiated the activity    |
| `FileName`                     | Process that executed                  |
| `ProcessCommandLine`           | Command executed by the child process  |
| `InitiatingProcessCommandLine` | Command line of the initiating process |

---

## 5. Office → LOLBin

Now investigate Office applications launching commonly abused Windows binaries.

### Mission 5

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "outlook.exe"
)
| where FileName in~ (
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessCommandLine
```

This query looks for relationships such as:

```text
WINWORD.EXE → mshta.exe
EXCEL.EXE   → rundll32.exe
OUTLOOK.EXE → regsvr32.exe
```

---

# 🧠 Mission 6 — Analyst Thinking

If I discover:

```text
WINWORD.EXE
      ↓
powershell.exe
```

I would investigate:

1. **Parent/initiating process** — Understand how PowerShell was launched.
2. **Command line** — Check for suspicious arguments, encoded commands, downloads, or obfuscation.
3. **Historical behavior** — Determine whether this is normal for the device/user or a new behavior.
4. **Network activity** — Check whether the process contacted suspicious internal or external destinations.
5. **File/registry activity** — Look for file creation, modification, or persistence mechanisms.
6. **Related activity** — Check what happened immediately before and after the PowerShell execution.

### Analyst mindset

> A suspicious process relationship is an investigation lead, not proof of compromise.

---

# 🔥 Bonus — Office → PowerShell Detection

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "outlook.exe"
)
| where FileName =~ "powershell.exe"
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessCommandLine
```

---

## 📚 KQL Concepts Learned

| Concept                        | Purpose                                            |
| ------------------------------ | -------------------------------------------------- |
| `DeviceProcessEvents`          | Endpoint process telemetry                         |
| `FileName`                     | Process that executed                              |
| `ProcessCommandLine`           | Command executed by the process                    |
| `InitiatingProcessFileName`    | Process that initiated the execution               |
| `InitiatingProcessCommandLine` | Command line of the initiating process             |
| `in~`                          | Case-insensitive matching against multiple values  |
| `has_any`                      | Search for multiple terms                          |
| `ago()`                        | Search a relative time period                      |
| LOLBin                         | Legitimate utility that can be abused by attackers |

---

## 🎯 Day 08 Key Takeaways

1. Process names alone are not enough for threat hunting.
2. `ProcessCommandLine` provides important execution context.
3. Parent/initiating process relationships can reveal suspicious execution chains.
4. Office applications launching PowerShell or LOLBins can deserve investigation.
5. LOLBins are legitimate tools and should not automatically be classified as malicious.
6. Historical behavior, network activity, and file/registry changes provide additional context.
7. Good threat hunting focuses on **behavior and relationships**, not just individual events.

---

## 🛡️ Security Focus

Today's investigation moved from:

> **"What process executed?"**

to:

> **"What process launched it, what did it execute, and what happened around it?"**

This is a fundamental concept in **endpoint threat hunting and detection engineering**.

---
Day 08 ✅ Windows Process Hunting
```
