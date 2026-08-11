# Day 02 — KQL Filtering with `where`

## 🎯 Objective

Learn how to filter security telemetry using the KQL `where` operator.

Today I learned:

* `where`
* `==`
* `!=`
* `or`
* Combining `where`, `take`, and `project`
* Filtering process activity for SOC investigations

---

# 1. `where`

### What does `where` do?

`where` filters records based on a condition.

It allows an analyst to narrow down a large dataset and focus on events that match a specific condition.

Example:

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
```

This query searches the `DeviceProcessEvents` table and returns only events where the process name is `powershell.exe`.

### SOC Perspective

Instead of reviewing every process execution on an endpoint, an analyst can filter specifically for a process that may be relevant to an investigation.

---

# 2. Equality — `==`

`==` means **equals**.

Example:

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
```

This means:

> Return only records where `FileName` is exactly `powershell.exe`.

---

# 3. Not Equal — `!=`

`!=` means **not equal to**.

Example:

```kql
DeviceProcessEvents
| where FileName != "chrome.exe"
```

This returns process events where the filename is not `chrome.exe`.

### SOC Use Case

This can be useful when an analyst wants to exclude known or irrelevant activity from an investigation.

However, excluding data should be done carefully because legitimate-looking processes can sometimes be involved in malicious activity.

---

# 🧪 Mission 1 — PowerShell Hunting

### Scenario

The SOC analyst is investigating potentially suspicious PowerShell activity.

The requirement is:

> Find PowerShell executions and display the timestamp, device, user, process name, and command line.

### Query

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### What the query does

```text
DeviceProcessEvents
        ↓
     where
        ↓
powershell.exe only
        ↓
     project
        ↓
Relevant investigation fields
```

### Why `ProcessCommandLine` matters

The process name alone may not tell us whether the activity is suspicious.

For example:

```text
powershell.exe
```

could be completely legitimate.

But the command line may reveal additional context such as:

```text
powershell.exe -EncodedCommand ...
```

or:

```text
powershell.exe -ExecutionPolicy Bypass ...
```

Therefore, `ProcessCommandLine` is an important field during PowerShell investigations.

---

# 🧪 Mission 2 — Limit the Results

### Scenario

The PowerShell query returns a large number of events.

The SOC manager asks:

> "Show me only 20 PowerShell events for an initial review."

### Query

```kql
DeviceProcessEvents
| where FileName == "powershell.exe"
| take 20
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Investigation flow

```text
All process events
       ↓
Filter PowerShell
       ↓
Take 20 events
       ↓
Display relevant fields
```

This demonstrates how multiple KQL operators can be combined into a single investigation query.

---

# 🧪 Mission 3 — CMD Investigation

### Scenario

The SOC team has received an alert involving `cmd.exe`.

The analyst wants to investigate command-shell executions.

### Query

```kql
DeviceProcessEvents
| where FileName == "cmd.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### Investigation fields

| Field                | Why it matters                        |
| -------------------- | ------------------------------------- |
| `Timestamp`          | Determines when the activity occurred |
| `DeviceName`         | Identifies the affected endpoint      |
| `AccountName`        | Identifies the associated user        |
| `FileName`           | Identifies the process                |
| `ProcessCommandLine` | Provides additional execution context |

---

# 🔥 Bonus Mission — Multiple Processes

### Scenario

The SOC analyst wants to investigate both PowerShell and CMD activity.

The requirement is:

> Find events where the process is either `cmd.exe` or `powershell.exe`.

### Query

```kql
DeviceProcessEvents
| where FileName == "cmd.exe" or FileName == "powershell.exe"
```

This uses the `or` logical operator.

The condition is satisfied when either of the two process names matches.

---

# 🧠 Understanding `or`

The logic is:

```text
FileName == "cmd.exe"
          OR
FileName == "powershell.exe"
```

Therefore:

| FileName         | Returned? |
| ---------------- | --------- |
| `cmd.exe`        | ✅         |
| `powershell.exe` | ✅         |
| `chrome.exe`     | ❌         |
| `explorer.exe`   | ❌         |

---

# ⭐ Improved Version

The bonus query can also be written using `in~`, which we will explore more deeply later:

```kql
DeviceProcessEvents
| where FileName in~ ("cmd.exe", "powershell.exe")
```

For now, remember:

```text
or
```

allows us to combine multiple conditions.

---

# 🔍 SOC Analyst Perspective

Today's queries introduce a major threat-hunting concept:

> **Don't investigate everything. Filter the telemetry based on the hypothesis you're testing.**

For example:

```text
Security Question
       ↓
"Is PowerShell being used?"
       ↓
      where
       ↓
PowerShell events
       ↓
Relevant evidence
```

This is the beginning of **hypothesis-driven threat hunting**.

---

# 📚 KQL Operators Learned

| Operator  | Purpose                                      |
| --------- | -------------------------------------------- |
| `where`   | Filters records based on a condition         |
| `==`      | Checks whether a value equals another value  |
| `!=`      | Checks whether a value is not equal          |
| `or`      | Combines multiple conditions                 |
| `take`    | Limits the number of returned rows           |
| `project` | Selects the columns to display               |
| `\|`      | Passes output from one operation to the next |

---

# 🎯 Day 2 Key Takeaways

1. `where` is used to filter records.
2. `==` checks for equality.
3. `!=` checks for inequality.
4. `or` allows multiple conditions to be combined.
5. `take` can reduce the number of results for initial analysis.
6. `project` keeps the investigation focused on relevant fields.
7. `ProcessCommandLine` can provide important context beyond the process name.
8. Filtering telemetry is one of the fundamental skills required for threat hunting.

---

# 🛡️ Security Concepts Practiced

Today's exercises introduced hunting around:

* PowerShell
* Windows Command Shell
* Process execution
* Command-line analysis
* Endpoint investigation

---
