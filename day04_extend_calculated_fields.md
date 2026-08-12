# Day 04 — KQL `extend` and Calculated Fields

## 🎯 Objective

Learn how to use `extend` to create new fields from existing telemetry and use those fields for threat hunting.

---

## 1. What is `extend`?

`extend` allows you to create a new column based on existing data.

Think of it like adding a new column to an Excel sheet.

```kql
DeviceProcessEvents
| extend ProcessLength = strlen(ProcessCommandLine)
| project FileName, ProcessCommandLine, ProcessLength
```

### `strlen()`

`strlen()` returns the number of characters in a string.

```kql
DeviceProcessEvents
| extend CommandLength = strlen(ProcessCommandLine)
```

If:

```text
ProcessCommandLine = "powershell.exe -NoProfile"
```

then `CommandLength` contains the number of characters in that command line.

---

## 🧪 Mission 1 — Calculate Command Length

```kql
DeviceProcessEvents
| extend CommandLength = strlen(ProcessCommandLine)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, CommandLength
```

### Learning

`extend` creates the `CommandLength` field, which can then be displayed using `project`.

---

## 2. `extend` + `where`

We can create a field and then filter on it.

```kql
DeviceProcessEvents
| extend CommandLength = strlen(ProcessCommandLine)
| where CommandLength > 200
| project Timestamp, DeviceName, FileName, ProcessCommandLine, CommandLength
```

This identifies process events where the command line contains more than 200 characters.

### SOC Perspective

Long command lines can sometimes indicate:

* Obfuscation
* Encoded commands
* Script execution
* Complex administrative commands

However, **command length alone does not prove malicious activity**.

---

## 🧪 Mission 2 — Long Command-Line Hunting

```kql
DeviceProcessEvents
| extend CommandLength = strlen(ProcessCommandLine)
| where CommandLength > 200
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, CommandLength
```

---

## 3. `extend` with String Functions

`extend` can also create normalized fields.

Example:

```kql
DeviceProcessEvents
| extend ProcessLower = tolower(FileName)
| project FileName, ProcessLower
```

If:

```text
FileName = PowerShell.EXE
```

then:

```text
ProcessLower = powershell.exe
```

This can help when telemetry contains inconsistent capitalization.

---

## 🧪 Mission 3 — Normalize Process Names

```kql
DeviceProcessEvents
| extend NormalizedProcess = tolower(FileName)
| project DeviceName, FileName, NormalizedProcess
```

---

## 🧪 Mission 4 — Suspicious PowerShell Hunting

### Objective

Find PowerShell executions where:

* The command line is longer than 200 characters.
* The command line contains `ExecutionPolicy`.
* The process name is PowerShell.
* Relevant investigation fields are displayed.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "ExecutionPolicy"
| extend CommandLength = strlen(ProcessCommandLine)
| where CommandLength > 200
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, CommandLength
```

### Why this is better

The original query attempted to use:

```kql
tolower(powershell.exe)
```

but `powershell.exe` is a literal value, not the `FileName` column.

Also, `ProcessName` was replaced with `FileName` because `DeviceProcessEvents` uses `FileName` for the process name in this hunting scenario.

---

## 🧪 Mission 5 — Analyst Thinking

A command line longer than 200 characters **does not automatically mean the activity is malicious**.

Legitimate administrative scripts, automation, software deployment, and other system-management tasks can also generate long command lines.

The analyst should investigate additional context such as:

* User
* Parent process
* Command line
* Script/file involved
* Network connections
* File reputation
* Persistence
* Activity before and after execution

Therefore:

> **A suspicious characteristic is an investigation signal, not proof of compromise.**

---

## 🔥 Bonus — Build a Mini Hunter

### Objective

Detect PowerShell executions where:

* PowerShell was executed.
* Command line is longer than 200 characters.
* `ExecutionPolicy` appears in the command line.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| extend CommandLength = strlen(ProcessCommandLine)
| where CommandLength > 200
| where ProcessCommandLine contains "ExecutionPolicy"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, CommandLength
```

### Hunting Logic

```text
Process Execution
       ↓
PowerShell
       ↓
Calculate Command Length
       ↓
CommandLength > 200
       ↓
ExecutionPolicy detected
       ↓
Investigate
```

---

## 📚 KQL Concepts Learned

| Operator / Function | Purpose                    |
| ------------------- | -------------------------- |
| `extend`            | Creates a new field        |
| `strlen()`          | Calculates string length   |
| `tolower()`         | Converts text to lowercase |
| `where`             | Filters records            |
| `contains`          | Searches within a string   |
| `=~`                | Case-insensitive equality  |
| `project`           | Selects relevant fields    |

---

## 🎯 Day 04 Key Takeaways

1. `extend` creates calculated or derived fields.
2. `strlen()` can help identify unusually long command lines.
3. `tolower()` can normalize text for analysis.
4. A derived field can be used with `where`.
5. Multiple conditions can create more focused hunting logic.
6. A suspicious indicator does not automatically mean malicious activity.
7. Good threat hunting requires **context and investigation**, not just a single query result.

---

## 🛡️ Security Focus

**MITRE ATT&CK:** T1059.001 — PowerShell

Today's exercise moved from simply finding PowerShell to identifying **PowerShell behavior that deserves further investigation**.

---

## 📁 GitHub

**File:**

```text
day04_extend_calculated_fields.md
```

**Commit:**

```text
Day 04: KQL extend and calculated fields
```

**Progress:**

```text
Day 01 ✅ KQL Basics
Day 02 ✅ Filtering
Day 03 ✅ String Hunting
Day 04 ✅ Calculated Fields
Day 05 ⏳ Aggregation with summarize
```
