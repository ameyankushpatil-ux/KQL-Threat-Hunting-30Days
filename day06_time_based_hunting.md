# Day 06 — KQL Time-Based Hunting

## 🎯 Objective

Learn how to use time-based KQL queries to investigate recent activity, specific time windows, and changes in activity over time.

---

## 1. `ago()`

`ago()` is used to look back from the current time.

Example:

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
```

This returns events from the last **1 hour**.

Common examples:

```text
ago(30m)  → Last 30 minutes
ago(1h)   → Last 1 hour
ago(24h)  → Last 24 hours
ago(7d)   → Last 7 days
```

### Mission 1 — PowerShell in the Last Hour

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

> **Note:** `=~` is the correct case-insensitive equality operator. `~=` is not the correct KQL operator.

---

## 2. `between`

`between` searches within a specific time range.

Concept:

```kql
Timestamp between (start .. end)
```

Example:

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-08-15 10:00:00) .. datetime(2026-08-15 12:00:00))
```

This searches for events between **10:00 AM and 12:00 PM**.

### Mission 2 — Specific Time Window

```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-08-15 10:00:00) .. datetime(2026-08-15 12:00:00))
| where FileName =~ "powershell.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

---

## 3. Combining Time + Threat Hunting

Time filters become much more useful when combined with hunting conditions.

Example:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "ExecutionPolicy"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

### What does this query answer?

> "Show me PowerShell executions containing `ExecutionPolicy` from the last 24 hours."

This is closer to a real threat-hunting query because we are combining:

```text
Time
 ↓
Process
 ↓
Command-line behavior
 ↓
Investigation fields
```

---

## 🧪 Mission 3 — Recent Suspicious PowerShell

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-env"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

This query searches for PowerShell activity containing `-env` during the last 24 hours.

**Important:** Finding `-env` alone does not prove malicious activity. The command line and surrounding telemetry require investigation.

---

## 4. Time + `summarize`

We can combine time filtering with the aggregation skills learned on Day 5.

Example:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| summarize Count = count() by FileName
| order by Count desc
```

This answers:

> "Which processes generated the most events during the last 24 hours?"

### Mission 4 — PowerShell Activity

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count() by FileName
| order by Count desc
```

Because we already filtered to PowerShell, this shows the total PowerShell activity during the selected period.

---

## 5. `bin()`

`bin()` groups timestamps into time intervals.

Example:

```kql
DeviceProcessEvents
| summarize Count = count() by bin(Timestamp, 1h)
```

Instead of examining every individual event, we can see activity by hour.

Example result:

```text
Time       Count
----------------
10:00       25
11:00       18
12:00       73
13:00       21
```

This helps identify **activity spikes**.

### Mission 5 — PowerShell Activity by Hour

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count() by bin(Timestamp, 1h)
| order by Timestamp asc
```

The `order by` was added to make the timeline easier to read chronologically.

---

# 🧠 Day 6 Analyst Challenge

### Scenario

A workstation normally executes around **5 PowerShell commands per hour**, but suddenly executes **80 PowerShell commands at 2:00 AM**.

This deserves investigation because the activity is unusual compared with the system's normal behavior.

The analyst should investigate:

* Historical PowerShell activity for the same device
* Whether the activity occurs regularly at that time
* User responsible for the execution
* Parent process
* PowerShell command line
* Scripts or files executed
* Network connections
* Persistence mechanisms
* Whether the activity is related to legitimate automation or administration

### My Learning

> I need to compare the current PowerShell activity with the normal baseline for the same device and time period. If the activity is unusual, I should investigate the user, command line, parent process, scripts, network connections, and persistence to determine whether the activity is legitimate or potentially malicious.

---

## 📚 KQL Concepts Learned

| Operator / Function | Purpose                           |
| ------------------- | --------------------------------- |
| `ago()`             | Searches relative time periods    |
| `between`           | Searches a specific time range    |
| `datetime()`        | Defines a specific date/time      |
| `bin()`             | Groups events into time intervals |
| `summarize`         | Aggregates events                 |
| `order by`          | Sorts results                     |
| `=~`                | Case-insensitive equality         |

---

## 🎯 Day 6 Key Takeaways

1. Time is critical when investigating security events.
2. `ago()` is useful for recent activity.
3. `between` is useful when investigating a known incident window.
4. `bin()` helps identify activity spikes over time.
5. Combining time filters with process and command-line conditions creates stronger hunting queries.
6. A sudden increase in activity should be compared against a historical baseline.
7. Unusual activity is an **investigation signal**, not automatically proof of malicious activity.

---

## 🛡️ Security Focus

Today's focus was **time-based PowerShell hunting**.

The investigation mindset changed from:

> "Did PowerShell execute?"

to:

> **"When did PowerShell execute, how frequently, and is that activity unusual for this endpoint?"**

---

## 📁 GitHub

**File:**

```text
day06_time_based_hunting.md
```

**Commit:**

```text
Day 06: KQL time-based hunting
```

### Progress

```text
Day 01 ✅ KQL Basics
Day 02 ✅ Filtering
Day 03 ✅ String Hunting
Day 04 ✅ Calculated Fields
Day 05 ✅ Aggregation
Day 06 ✅ Time-Based Hunting
Day 07 ⏳ Advanced Filtering and Logical Operators
```
