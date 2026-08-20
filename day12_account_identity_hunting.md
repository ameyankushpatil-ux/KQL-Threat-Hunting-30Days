# Day 12 — KQL Account & Identity Hunting

## 🎯 Objective

Use KQL to understand **which accounts are performing process activity**, which devices they are using, and whether their behavior requires further investigation.

Today I practiced:

* Account-based hunting
* PowerShell activity by user
* User + device analysis
* LOLBin activity by account
* Suspicious PowerShell by account
* Account/device behavioral baselines

---

## 1. Account Process Activity

`AccountName` helps identify the account associated with process execution.

### Mission 1

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine
```

### Correction

The original query placed `project` after `where`:

```kql
| where project ...
```

`project` is a separate operator and should be used directly after the time filter.

---

## 2. Top PowerShell Users

Instead of looking at individual events, `summarize` helps identify which accounts execute PowerShell most frequently.

### Mission 2

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count() by AccountName
| order by Count desc
```

This answers:

> **Which accounts executed PowerShell most frequently during the last 24 hours?**

High activity does not automatically indicate compromise.

---

## 3. PowerShell by User + Device

A user may legitimately use PowerShell on one endpoint.

The same account suddenly appearing across multiple endpoints can provide additional context.

### Mission 3

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count() by AccountName, DeviceName
| order by Count desc
```

This gives visibility into:

```text
Account
   ↓
Device
   ↓
PowerShell activity
```

---

## 4. LOLBin Activity by Account

Investigate accounts using commonly abused Windows utilities.

### Mission 4

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ (
    "powershell.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "certutil.exe"
)
| summarize Count = count() by AccountName
| order by Count desc
```

This identifies which accounts generate the highest volume of activity involving these processes.

> **Important:** LOLBins are legitimate Windows utilities. Their presence alone does not indicate malicious activity.

---

## 5. Account Baseline

### Mission 5

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| summarize Count = count() by AccountName
| order by Count desc
```

This gives an initial account activity baseline.

### Investigation Focus

If accounts such as:

```text
john
svc_backup
administrator
SYSTEM
```

appear frequently, I should not immediately classify them as malicious.

I would focus on accounts such as `john` and `svc_backup` and investigate:

* What processes they execute
* Which devices they use
* Whether the activity is expected
* When the activity occurs
* Whether the behavior changed from the normal baseline

---

## 6. Suspicious PowerShell by Account

Now combine account hunting with the PowerShell indicators learned on Day 9.

### Mission 6

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "ExecutionPolicy",
    "DownloadString",
    "IEX"
)
| summarize Count = count() by AccountName, DeviceName
| order by Count desc
```

This helps identify:

> **Which account/device combinations generated suspicious PowerShell activity?**

---

## 🔥 Mission 7 — Account-Based Threat Hunter

Combine:

* Recent activity
* Suspicious Windows processes
* Suspicious PowerShell indicators
* Account
* Device

### Improved Query

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ (
    "powershell.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "certutil.exe"
)
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "ExecutionPolicy",
    "DownloadString",
    "IEX"
)
| summarize Count = count() by AccountName, DeviceName
| order by Count desc
```

### Hunting Logic

```text
Last 24 hours
      ↓
Suspicious / abused processes
      ↓
Suspicious command-line indicators
      ↓
Account + Device
      ↓
Prioritize investigation
```

---

# 🧠 Analyst Challenge

Suppose the results show:

```text
AccountName      DeviceName       Count
----------------------------------------
john             PC-102             2
svc_backup       PC-Backup         85
administrator    PC-Admin           4
```

`svc_backup` has the highest count, but this **does not automatically mean the account is compromised**.

I would investigate:

1. What is the purpose of `svc_backup`?
2. Is PowerShell expected for this account?
3. What commands were executed?
4. Which devices normally use this account?
5. What time did the activity occur?
6. Was the activity automated or interactive?
7. Did the account access other systems?
8. Were authentication failures observed?
9. Did the account create processes or persistence?
10. Does the activity match its historical baseline?

### Key Lesson

> **Account activity must be evaluated against the account's expected role and normal behavior.**

---

## 📚 KQL Concepts Learned

| KQL           | Purpose                                           |
| ------------- | ------------------------------------------------- |
| `AccountName` | Identifies the account associated with activity   |
| `summarize`   | Aggregates events                                 |
| `count()`     | Counts events                                     |
| `in~`         | Case-insensitive matching against multiple values |
| `has_any()`   | Searches for multiple terms                       |
| `ago()`       | Searches recent activity                          |
| `order by`    | Ranks results                                     |
| `project`     | Selects relevant fields                           |

---

## 🎯 Day 12 Key Takeaways

1. Process activity should be investigated in the context of the **account** that performed it.
2. `summarize` can identify high-volume accounts.
3. Combining `AccountName + DeviceName` provides better context.
4. Service accounts should be compared against their expected behavior.
5. High activity does not automatically mean compromise.
6. Suspicious process + suspicious command line + unusual account/device behavior creates a stronger investigation lead.
7. Baselines are essential for distinguishing normal administrative activity from potentially malicious behavior.
