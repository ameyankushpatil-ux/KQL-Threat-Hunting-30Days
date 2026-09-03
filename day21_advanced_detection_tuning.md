On Day 20, we learned that simply detecting:

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
```

can generate too many alerts.

Today, we will improve the detection by asking:

> **What does normal behavior look like, and what behavior is unusual for this user or device?**

The goal is to detect **behavioral anomalies**, not just suspicious keywords.

---

# 🔎 Mission 1 — Baseline PowerShell Activity

Start by understanding PowerShell usage across users and devices.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count()
    by AccountName, DeviceName
| order by Count desc
```

### Analyst Question

Which accounts and devices generate the most PowerShell activity?

A high count is **not automatically malicious**. It may indicate administration or automation.

---

# 🔎 Mission 2 — Identify Common PowerShell Commands

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count()
    by ProcessCommandLine
| order by Count desc
```

### Analyst Question

Which commands are:

* Common?
* Rare?
* Associated with automation?
* Worth investigating?

This establishes a command-line baseline.

---

# 🔎 Mission 3 — Detect Rare Suspicious Commands

Now search for PowerShell commands containing known suspicious indicators.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "EncodedCommand",
    "DownloadString",
    "Invoke-WebRequest",
    "IEX",
    "FromBase64String"
)
| summarize Count = count()
    by AccountName,
             DeviceName,
             ProcessCommandLine
| order by Count asc
```

### Why `order by Count asc`?

We are interested in **rare suspicious behavior**.

Rare does not mean malicious, but it can provide a valuable investigation lead.

---

# 🔎 Mission 4 — Build a Time-Based Behavioral Baseline

Look at PowerShell activity over the last 7 days.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "powershell.exe"
| summarize Count = count()
    by bin(Timestamp, 1h)
| order by Timestamp asc
```

### Analyst Question

Can you identify:

* Normal working-hour activity?
* Unusual spikes?
* Activity during normally quiet periods?

A sudden spike may be more interesting when combined with other suspicious behavior.

---

# 🔎 Mission 5 — Find Unusual Parent Processes

PowerShell normally has many legitimate parent processes.

Let's identify which parent processes are launching it.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| summarize Count = count()
    by InitiatingProcessFileName
| order by Count asc
```

### Analyst Thinking

Suppose you see:

```text
explorer.exe       → common
services.exe       → common
WINWORD.EXE        → rare
EXCEL.EXE          → rare
OUTLOOK.EXE        → rare
```

A rare parent-child relationship deserves investigation.

---

# 🚨 Mission 6 — High-Confidence Multi-Signal Detection

Now combine several signals.

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
    "FromBase64String"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
| order by Timestamp desc
```

### Detection Logic

```text
Office Application
       ↓
PowerShell
       ↓
Suspicious Command
       ↓
Potential Investigation
```

This is much stronger than detecting PowerShell alone.

---

# 🧠 Mission 7 — Add a Simple Risk Score

Detection engineering can assign different priorities to different behaviors.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| extend RiskScore = case(
    ProcessCommandLine has_any (
        "EncodedCommand",
        "DownloadString",
        "Invoke-WebRequest",
        "IEX"
    )
    and InitiatingProcessFileName in~ (
        "WINWORD.EXE",
        "EXCEL.EXE",
        "OUTLOOK.EXE"
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

```text
Risk 90 → Office → PowerShell → Suspicious Command
Risk 60 → PowerShell → Suspicious Command
Risk 20 → Normal PowerShell
```

> A risk score does not prove compromise. It helps analysts prioritize investigation.

---

# 🧪 Analyst Challenge

Imagine your detection generates:

```text
100 alerts/day
```

After analysis:

```text
70 → Normal automation
20 → IT administration
7  → Security testing
2  → Unknown behavior
1  → Highly suspicious behavior
```

### Your task

Design a tuning strategy that:

1. Reduces unnecessary alerts.
2. Does not blindly exclude PowerShell.
3. Preserves suspicious Office → PowerShell activity.
4. Considers account and device context.
5. Prioritizes rare + suspicious behavior.

### Think Like a Detection Engineer

Ask:

```text
Is the account expected?
        ↓
Is the device expected?
        ↓
Is the parent process expected?
        ↓
Is the command expected?
        ↓
Is the behavior rare?
        ↓
Is there additional network/file activity?
        ↓
What severity should the alert receive?
```

---

# 🛡️ Detection Engineering Notes

### Detection Quality

A good detection should balance:

**Coverage + Accuracy + Context + Maintainability**

Avoid:

```text
PowerShell = Alert
```

Prefer:

```text
Unexpected User
+
Unusual Device
+
Office Parent
+
PowerShell
+
Suspicious Command
+
Rare Behavior
```

The more contextual signals available, the better the analyst can prioritize the event.

---

## 📌 Key Takeaways

* Establish a behavioral baseline before tuning.
* Rare behavior can be more valuable than high-volume behavior.
* Parent-child relationships provide important context.
* Time-based baselines help identify unusual activity.
* Multiple weak signals can create a stronger detection.
* Risk scoring helps prioritize analyst investigations.
* False-positive reduction should **not** come at the cost of detection coverage.

### 🔥 Detection Engineering Principle

> **Don't ask only "Is this command suspicious?" Ask "Is this behavior unusual for this user, device, and context?"**
