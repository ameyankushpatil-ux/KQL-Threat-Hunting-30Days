# Day 07 — KQL Advanced Filtering and Logical Operators

## 🎯 Objective

Learn how to combine multiple filtering conditions and search for multiple values efficiently.

Today I learned:

* `in`
* `in~`
* `and`
* `or`
* `has_any`
* Combining multiple hunting conditions

---

## 1. `in`

`in` matches a value against a list of values.

Instead of:

```kql
DeviceProcessEvents
| where FileName == "cmd.exe"
    or FileName == "powershell.exe"
    or FileName == "wscript.exe"
```

We can use:

```kql
DeviceProcessEvents
| where FileName in ("cmd.exe", "powershell.exe", "wscript.exe")
```

### Mission 1 — LOLBin Hunting

```kql
DeviceProcessEvents
| where FileName in ("rundll32.exe", "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

**Learning:** `in` makes multiple-value filtering shorter and easier to maintain.

---

## 2. `in~`

`in~` performs **case-insensitive matching**.

Example:

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "cmd.exe")
```

It can match variations such as:

```text
powershell.exe
PowerShell.exe
POWERSHELL.EXE
```

### Mission 2 — Case-Insensitive Process Hunting

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

---

## 3. `and`

`and` means **both conditions must be true**.

Example:

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "ExecutionPolicy"
```

Logical thinking:

```text
PowerShell
    AND
ExecutionPolicy
```

### Mission 3 — PowerShell + Bypass

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "ExecutionPolicy"
    and ProcessCommandLine contains "Bypass"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

**Learning:** Both `ExecutionPolicy` and `Bypass` must be present in the command line.

---

## 4. `or`

`or` means **at least one condition must be true**.

Example:

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "EncodedCommand"
    or ProcessCommandLine contains "ExecutionPolicy"
```

### Mission 4 — PowerShell Indicators

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "EncodedCommand"
    or ProcessCommandLine contains "ExecutionPolicy"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

**Learning:** The event is returned if either indicator is present.

---

## 5. `has_any`

`has_any` allows us to search for any term from a list.

Example:

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("whoami", "ipconfig", "systeminfo")
```

This is useful when hunting for multiple related commands.

### Mission 5 — Discovery Hunting

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("whoami", "ipconfig", "systeminfo", "net user", "tasklist")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

This query searches PowerShell command lines for several common discovery commands.

---

# 🔥 Mission 6 — Full SOC Hunting Query

### Objective

Investigate recent execution of commonly abused Windows processes where suspicious command-line indicators are present.

The hunting requirements are:

```text
Last 24 hours
        ↓
PowerShell / CMD / MSHTA / Rundll32
        ↓
EncodedCommand / ExecutionPolicy / DownloadString
        ↓
Relevant investigation fields
```

### Corrected Query

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "cmd.exe", "mshta.exe", "rundll32.exe")
| where ProcessCommandLine has_any ("EncodedCommand", "ExecutionPolicy", "DownloadString")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Why this is better than my first attempt

The original query had several syntax problems:

```text
FileName =~ ("powershell.exe","cmd.exe",...)
```

`=~` compares one value, so for multiple values we use:

```kql
FileName in~ ("powershell.exe", "cmd.exe", ...)
```

Also:

```text
Process CommandLineConatains
```

is not valid KQL syntax.

The correct field is:

```text
ProcessCommandLine
```

and the operator is:

```text
has_any
```

---

## 🧠 SOC Analyst Thinking

Mission 6 combines several concepts:

```text
Time
 ↓
Process filtering
 ↓
Multiple-value matching
 ↓
Command-line hunting
 ↓
Relevant evidence
```

However, finding one of these indicators does **not automatically mean the process is malicious**.

The analyst should investigate:

* Parent process
* User
* Device
* Full command line
* Script/file involved
* Network connections
* Persistence
* Process activity before and after the event
* Whether the activity is legitimate administration or automation

---

## 📚 KQL Concepts Learned

| Operator  | Purpose                                  |
| --------- | ---------------------------------------- |
| `in`      | Match a value against multiple values    |
| `in~`     | Case-insensitive multiple-value matching |
| `and`     | Both conditions must be true             |
| `or`      | At least one condition must be true      |
| `has_any` | Match any term from a list               |
| `ago()`   | Search a relative time period            |
| `=~`      | Case-insensitive equality                |
| `project` | Select relevant fields                   |

---

## 🎯 Week 1 Key Takeaways

I can now combine basic KQL operators to build a simple hunting query.

My progression:

```text
Day 01 → take + project
Day 02 → where
Day 03 → String hunting
Day 04 → extend
Day 05 → summarize
Day 06 → Time-based hunting
Day 07 → Advanced filtering
```

### Week 1 Hunting Mindset

Instead of simply asking:

> "Is PowerShell running?"

I can now ask:

> **"Which suspicious processes ran recently, what command-line indicators were present, and which user/device was involved?"**

This is the foundation for more advanced **threat hunting and detection engineering**.

---

We'll start using everything from Week 1 to investigate **Windows process execution**, including suspicious parent-child relationships and LOLBins.
