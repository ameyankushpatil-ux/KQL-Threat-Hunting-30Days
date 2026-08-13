# Day 05 — KQL `summarize` and Aggregation

## 🎯 Objective

Learn how to use `summarize` to aggregate security telemetry and identify patterns across large numbers of events.

---

## 1. What is `summarize`?

`summarize` is used to **aggregate data**.

Think of it like creating a **summary or pivot table in Excel**.

Example:

```kql
DeviceProcessEvents
| summarize Count = count()
```

This calculates the total number of records in the `DeviceProcessEvents` table.

---

## 2. `count()`

`count()` counts the number of records.

Example:

```kql
DeviceProcessEvents
| summarize Count = count()
```

### Task 1 — Total Process Events

```kql
DeviceProcessEvents
| summarize Count = count()
```

### SOC Perspective

A total event count gives an analyst an initial understanding of the amount of telemetry being investigated.

---

## 3. `summarize ... by`

`summarize` becomes more useful when combined with `by`.

Example:

```kql
DeviceProcessEvents
| summarize Count = count() by FileName
```

This counts how many times each process appears in the telemetry.

Conceptually:

```text
FileName          Count
-----------------------
chrome.exe        5000
explorer.exe      3200
powershell.exe     250
cmd.exe            180
```

### Task 2 — Process Frequency

```kql
DeviceProcessEvents
| summarize Count = count() by FileName
```

---

## 4. `order by`

`order by` sorts the results.

Example:

```kql
| order by Count desc
```

`desc` means:

> Highest value → Lowest value

### Mission 3 — Sort Process Activity

```kql
DeviceProcessEvents
| summarize Count = count() by FileName
| order by Count desc
```

This puts the most frequently observed processes at the top.

---

## 5. `top`

`top` can limit the results to the highest values.

Example:

```kql
DeviceProcessEvents
| summarize Count = count() by FileName
| top 10 by Count
```

This returns the **10 most frequently observed processes**.

### Mission 4 — Top 10 Processes

```kql
DeviceProcessEvents
| summarize Count = count() by FileName
| top 10 by Count
```

---

## 🔥 Mission 5 — PowerShell Activity by Device and User

### Objective

Identify which users and endpoints execute PowerShell most frequently.

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| summarize Count = count() by DeviceName, AccountName
| order by Count desc
```

### Hunting Logic

```text
All Process Events
       ↓
PowerShell only
       ↓
Count executions
       ↓
Group by Device + User
       ↓
Sort highest → lowest
```

This can help identify users or endpoints with unusually high PowerShell activity.

---

## 🧠 Analyst Thinking

A high number of PowerShell executions **does not automatically mean compromise**.

For example, high PowerShell activity could be caused by:

* System administration
* Automation
* Software deployment
* IT scripts
* Developer activity
* Backup or monitoring tools

The analyst should investigate additional context:

* What commands were executed?
* Which parent process launched PowerShell?
* Which user executed it?
* Which endpoint was involved?
* Were external connections made?
* Was there persistence?
* Is this activity normal for this user/device?

Therefore:

> **`summarize` helps identify patterns; it does not by itself determine whether activity is malicious.**

---

## 📚 KQL Concepts Learned

| Operator / Function | Purpose                   |
| ------------------- | ------------------------- |
| `summarize`         | Aggregates data           |
| `count()`           | Counts records            |
| `by`                | Groups results            |
| `order by`          | Sorts results             |
| `desc`              | Sorts highest → lowest    |
| `top`               | Returns the top results   |
| `=~`                | Case-insensitive equality |

---

## 🎯 Day 05 Key Takeaways

1. `summarize` is used to aggregate telemetry.
2. `count()` counts events.
3. `by` allows events to be grouped by fields.
4. `order by` helps rank the results.
5. `top` helps focus on the most important/highest-volume results.
6. Aggregation is useful for discovering patterns in large datasets.
7. High event volume is an investigation signal, not proof of malicious activity.

---

## 🛡️ Security Focus

Today's focus was **PowerShell activity analysis**.

Instead of asking:

> "Did PowerShell execute?"

we can now ask:

> **"Which users and endpoints are executing PowerShell most frequently?"**

This is the beginning of **behavior-based threat hunting**.

---

## 📁 GitHub

**File:**

```text
day05_summarize_aggregation.md
```

**Commit:**

```text
Day 05: KQL summarize and aggregation
```

### Progress

```text
Day 01 ✅ KQL Basics
Day 02 ✅ Filtering
Day 03 ✅ String Hunting
Day 04 ✅ Calculated Fields
Day 05 ✅ Aggregation
Day 06 ⏳ Time-based Hunting
```
