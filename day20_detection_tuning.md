# 🟢 Day 20 — KQL Mission: Detection Tuning & False Positive Reduction

**⏱️ Time:** 30 Minutes
**🎯 Level:** Detection Engineering → Advanced Threat Hunting
**📌 Focus:** Detection Tuning, Baseline, False Positives & Context

---

## 🎯 Objective

A detection rule may initially produce a large number of results.

For example:

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
```

This detects PowerShell activity, but **PowerShell itself is not malicious**.

A SOC analyst must determine:

* What activity is normal?
* Which users/devices commonly generate it?
* Which commands are expected?
* Which combinations of behaviors are suspicious?

This process is called **Detection Tuning**.

> **Detection Tuning = Improving a detection so that it produces useful alerts while reducing unnecessary false positives.**

---

# 🔎 Mission 1 — Establish a Baseline

First, understand who commonly runs PowerShell.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count()
    by AccountName, DeviceName
| order by Count desc
```

### Why?

This helps identify:

* Frequent PowerShell users
* Devices generating high PowerShell activity
* Potential automation/service accounts

A high count does **not** automatically mean malicious activity.

---

# 🔎 Mission 2 — Identify Common Commands

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count()
    by ProcessCommandLine
| order by Count desc
```

### Analyst Question

Which commands appear frequently?

If a command is consistently used by approved automation, it may deserve a lower priority.

---

# 🔎 Mission 3 — Office → PowerShell Hunting

Office applications spawning PowerShell can be suspicious, especially when combined with suspicious PowerShell indicators.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE",
    "EXCEL.EXE",
    "OUTLOOK.EXE"
)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX",
    "ExecutionPolicy"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

### Why is this stronger?

Instead of detecting:

> PowerShell

we detect:

> **Office → PowerShell → Suspicious Command**

Multiple signals provide better context and generally reduce noise.

---

# 🔎 Mission 4 — Baseline by User and Device

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count()
    by AccountName, DeviceName, InitiatingProcessFileName
| order by Count desc
```

This helps identify the **normal parent process** for PowerShell execution.

For example:

```text
Account        Device       Parent Process       Count
-------------------------------------------------------
admin          PC-01        explorer.exe         250
user1          PC-02        WINWORD.EXE           2
user2          PC-03        EXCEL.EXE             1
```

A rare Office → PowerShell relationship may deserve more investigation than common administrative activity.

---

# 🔎 Mission 5 — Build a Time-Based Baseline

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| summarize Count = count()
    by bin(Timestamp, 1h)
| order by Timestamp asc
```

### Why `bin()`?

`bin()` groups events into time windows.

This allows analysts to identify:

* Normal hourly activity
* Activity spikes
* Unusual periods of PowerShell execution

---

# 🔎 Mission 6 — Find Rare PowerShell Behavior

Instead of looking only at the most common commands, look for **rare combinations**.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count()
    by AccountName, DeviceName, ProcessCommandLine
| order by Count asc
```

Rare behavior is not automatically malicious, but it can provide useful investigation leads.

---

# 🚨 Mission 7 — Tuned Detection

Combine context and suspicious behavior into a higher-quality detection.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "WINWORD.EXE",
    "EXCEL.EXE",
    "OUTLOOK.EXE"
)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX",
    "ExecutionPolicy"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

---

# 🧠 Analyst Challenge — Reduce Alert Noise

Imagine your detection produces:

```text
100 alerts/day

80  → Legitimate automation
15  → Security administration
4   → Suspicious but benign testing
1   → Potentially malicious
```

### Question

Would you simply suppress the other 99 events?

**No.**

Instead, investigate **why** those events are legitimate.

### Expected Activity

```text
Expected Automation
        ↓
Expected Device
        ↓
Expected Account
        ↓
Expected Command
        ↓
Lower Priority
```

### Suspicious Activity

```text
Unknown User
      ↓
Office Application
      ↓
PowerShell
      ↓
EncodedCommand
      ↓
External Network
      ↓
Higher Priority
```

The goal is not simply to reduce alert volume.

> **The goal is to increase the signal-to-noise ratio without hiding real attacks.**

---

# 🛡️ Detection Documentation

**Detection Name:**
`Office → PowerShell Suspicious Execution`

**Purpose:**
Detect suspicious PowerShell execution originating from Microsoft Office applications.

**Data Source:**
`DeviceProcessEvents`

**Severity:**
Medium / High — depending on additional context.

**Detection Logic:**

```text
Office Parent
      +
PowerShell Child
      +
Suspicious PowerShell Command
```

**Potential False Positives:**

* Legitimate administrative automation
* Approved PowerShell scripts
* Security testing
* IT automation

**Tuning Strategy:**

Validate:

* Account
* Device
* Parent process
* Command line
* Execution frequency
* Network activity
* File activity

**Investigation:**

Correlate with:

```text
Process
  ↓
Network Connection
  ↓
File Creation
  ↓
Hash
  ↓
Persistence
```

---

## 📌 Key Takeaways

* **Detection ≠ Alert**
* Baseline normal activity before tuning.
* `summarize` helps identify common behavior.
* `bin()` helps establish time-based baselines.
* Rare activity deserves investigation, not automatic blocking.
* Context such as **user + device + parent process + command line** improves detection quality.
* Multiple weak signals can form a stronger detection.
* Never suppress alerts blindly just to reduce alert volume.

**Day 21 → Advanced Detection Tuning & Behavioral Baselines**
