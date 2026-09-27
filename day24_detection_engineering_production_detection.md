Day 24 is the next major step: turning the hunting logic you've built into a **production-style detection** with severity, confidence, tuning, and investigation fields.

# 🟢 Day 24 — KQL Mission: From Hunting Query to Production Detection

**⏱️ Time:** 30 Minutes
**🎯 Level:** Advanced Detection Engineering
**📌 Focus:** Detection Logic, Severity, Risk Scoring, Alert Context, Tuning & Production Readiness

---

## 🎯 Objective

During Days 1–23, we learned how to:

```text
KQL Basics
   ↓
Threat Hunting
   ↓
Behavioral Analysis
   ↓
Cross-Table Correlation
   ↓
Attack-Chain Hunting
```

Today we take the next step:

> **How do we turn a hunting query into a detection that a SOC can actually operate?**

A hunting query answers:

> "Can I find this behavior?"

A detection should answer:

> "When should the SOC be alerted, how important is it, and what information should the analyst investigate?"

---

# 🧠 Mission 1 — Start With a Hunting Query

Begin with suspicious PowerShell.

```kql id="2w5v1p"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          ProcessCommandLine
```

This is useful for hunting.

But it is still relatively broad.

---

# 🔎 Mission 2 — Add Context

Add the parent process and suspicious Office relationship.

```kql id="hj2f4a"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX"
)
| extend ParentIsOffice = InitiatingProcessFileName in~ (
    "WINWORD.EXE",
    "EXCEL.EXE",
    "OUTLOOK.EXE"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          ParentIsOffice,
          ProcessCommandLine
```

Now the detection has more context.

```text
PowerShell
   +
Suspicious Command
   +
Office Parent
```

---

# 🚨 Mission 3 — Create a Risk Score

Use `case()` to assign different risk levels.

```kql id="0t8k9d"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| extend RiskScore = case(
    InitiatingProcessFileName in~ (
        "WINWORD.EXE",
        "EXCEL.EXE",
        "OUTLOOK.EXE"
    )
    and ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX"
    ), 90,

    ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX"
    ), 60,

    20
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          ProcessCommandLine,
          RiskScore
| order by RiskScore desc
```

### Example

```text id="7gqk1e"
90 → Office + PowerShell + suspicious command
60 → PowerShell + suspicious command
20 → PowerShell activity
```

The score is a **prioritization mechanism**, not proof of maliciousness.

---

# 🔎 Mission 4 — Convert Risk Into Severity

Now create an analyst-friendly severity field.

```kql id="frh8os"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| extend RiskScore = case(
    InitiatingProcessFileName in~ (
        "WINWORD.EXE",
        "EXCEL.EXE",
        "OUTLOOK.EXE"
    )
    and ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX"
    ), 90,

    ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX"
    ), 60,

    20
)
| extend Severity = case(
    RiskScore >= 80, "High",
    RiskScore >= 50, "Medium",
    "Low"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          ProcessCommandLine,
          RiskScore,
          Severity
| order by RiskScore desc
```

### Detection Flow

```text
Behavior
   ↓
Risk Score
   ↓
Severity
   ↓
Analyst Priority
```

---

# 🔎 Mission 5 — Add Detection Metadata

A production-style detection should explain what it detected.

```kql id="i0jvup"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX"
)
| extend DetectionName = "Suspicious PowerShell Execution"
| extend DetectionType = "PowerShell Threat Hunting"
| extend DataSource = "DeviceProcessEvents"
| project Timestamp,
          DetectionName,
          DetectionType,
          DataSource,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          ProcessCommandLine
```

### Why?

An alert should provide enough information for another analyst to understand **what triggered it**.

---

# 🔎 Mission 6 — Build an Investigation-Friendly Detection

Now combine:

* Detection name
* Severity
* Risk score
* User
* Device
* Parent process
* Command line

```kql id="jps9lz"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX"
)
| extend RiskScore = case(
    InitiatingProcessFileName in~ (
        "WINWORD.EXE",
        "EXCEL.EXE",
        "OUTLOOK.EXE"
    )
    and ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX"
    ), 90,

    60
)
| extend Severity = case(
    RiskScore >= 80, "High",
    RiskScore >= 50, "Medium",
    "Low"
)
| extend DetectionName = "Suspicious PowerShell Execution"
| project Timestamp,
          DetectionName,
          Severity,
          RiskScore,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine,
          SHA256
| order by RiskScore desc
```

This is much closer to a **SOC-ready detection output**.

---

# 🧪 Mission 7 — Detection Engineering Challenge

Imagine your detection produces:

```text id="sgl5po"
500 events/day
```

After analysis:

```text
350 → Normal PowerShell
100 → IT automation
30  → Security testing
15  → Unusual activity
5   → High-priority investigation leads
```

### Your task

Don't simply exclude everything except the 5 events.

Instead, improve the detection using context:

```text
Account
   +
Device
   +
Parent Process
   +
Command Line
   +
Time
   +
Network
   +
File Activity
```

The objective is to reduce noise **without creating blind spots**.

---

# 🚨 Bonus — Add Network Context

Use the Day 23 correlation technique to investigate high-risk PowerShell.

Conceptually:

```text
High-Risk PowerShell
        ↓
Network Activity
        ↓
Remote IP / URL
        ↓
File Creation
        ↓
Further Investigation
```

A production detection can trigger the initial alert while the analyst pivots into additional telemetry.

---

# 🛡️ Production Detection Documentation

## Detection Name

**Suspicious PowerShell Execution**

### Purpose

Identify PowerShell activity containing suspicious command-line indicators and prioritize events based on contextual risk.

### Data Source

`DeviceProcessEvents`

### Detection Logic

```text
PowerShell
    +
Suspicious Command
    +
Context
    ↓
Risk Score
    ↓
Severity
```

### Potential False Positives

* IT automation
* Administrative scripts
* Security testing
* Approved PowerShell tooling

### Tuning

Validate:

* Account
* Device
* Parent process
* Command line
* Frequency
* Network activity
* File activity

### Investigation

Pivot into:

```text
DeviceProcessEvents
        ↓
DeviceNetworkEvents
        ↓
DeviceFileEvents
        ↓
DeviceLogonEvents
```

---

# 📌 Key Takeaways

* A hunting query and production detection have different purposes.
* Good detections provide **context**, not just a trigger.
* `case()` can help create risk scores and severity.
* Detection metadata improves analyst usability.
* False-positive reduction should preserve meaningful coverage.
* A detection should tell the analyst **what happened and where to investigate next**.
* Cross-table correlation can provide additional evidence after the initial detection.

### 🔥 Detection Engineering Principle

> **A good detection doesn't just generate an alert — it gives the analyst a useful starting point for investigation.**

---
