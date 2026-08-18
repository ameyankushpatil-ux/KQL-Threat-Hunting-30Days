# Day 10 — Parent-Child Process Hunting

## 🎯 Objective

Learn how to investigate **process relationships** using KQL.

Instead of only asking:

> "What process executed?"

we now ask:

> **"Which process launched it, what command did it execute, and does the process chain make sense?"**

---

## 1. PowerShell Parent Process

Important fields:

```text
InitiatingProcessFileName
→ Parent / initiating process

FileName
→ Child process

InitiatingProcessCommandLine
→ Parent command line

ProcessCommandLine
→ Child command line
```

### Mission 1 — Find PowerShell's Parent

```kql id="v1k0xe"
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where Timestamp > ago(24h)
| project Timestamp,
          InitiatingProcessFileName,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine
```

This helps identify which process launched PowerShell.

---

## 2. Office → PowerShell

Office applications launching PowerShell can be an important investigation lead.

Examples:

```text
WINWORD.EXE  → powershell.exe
EXCEL.EXE    → powershell.exe
OUTLOOK.EXE  → powershell.exe
POWERPNT.EXE → powershell.exe
```

### Mission 2

```kql id="wh6q1p"
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "outlook.exe",
    "powerpnt.exe"
)
| where FileName =~ "powershell.exe"
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

### SOC Perspective

Office → PowerShell is **not automatically malicious**, but it deserves investigation when combined with suspicious command lines, unusual users, documents, or network activity.

---

## 3. Browser → PowerShell

Investigate browsers launching PowerShell:

```text
Chrome  → PowerShell
Edge    → PowerShell
Firefox → PowerShell
```

### Mission 3

```kql id="d6ecp8"
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "chrome.exe",
    "msedge.exe",
    "firefox.exe"
)
| where FileName =~ "powershell.exe"
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

This can help identify unusual browser-to-shell execution chains.

---

## 4. Office → LOLBin

Commonly abused Windows binaries include:

```text
mshta.exe
rundll32.exe
regsvr32.exe
```

### Mission 4

```kql id="f3o0y8"
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "outlook.exe"
)
| where FileName in~ (
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe"
)
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

### Why this matters

The relationship:

```text
Office
  ↓
LOLBin
```

can be more interesting than seeing a LOLBin by itself.

---

## 5. Office → Script Host

Script hosts can also be abused for execution.

Examples:

```text
wscript.exe
cscript.exe
mshta.exe
```

### Mission 5

```kql id="4gqjv5"
DeviceProcessEvents
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "outlook.exe"
)
| where FileName in~ (
    "wscript.exe",
    "cscript.exe",
    "mshta.exe"
)
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

---

## 6. Multi-Level Process Investigation

A suspicious chain may look like:

```text
WINWORD.EXE
     ↓
powershell.exe
     ↓
cmd.exe
     ↓
certutil.exe
```

The important point is that each process event can provide information about its **initiating process**.

### Mission 6

```kql id="d8ak1q"
DeviceProcessEvents
| where InitiatingProcessFileName =~ "powershell.exe"
| where FileName =~ "cmd.exe"
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

This specifically finds:

```text
PowerShell → CMD
```

### Improvement

Your original Mission 6 searched for `"cmd.exe"` inside the command line. That can produce false positives because a command line can mention `cmd.exe` without actually launching it.

Using:

```kql
InitiatingProcessFileName =~ "powershell.exe"
| where FileName =~ "cmd.exe"
```

directly investigates the actual process relationship.

---

# 🧠 Mission 7 — Analyst Investigation

Scenario:

```text
02:15 AM
     ↓
WINWORD.EXE
     ↓
PowerShell
     ↓
CMD
     ↓
certutil.exe
```

This deserves **high-priority investigation** because several signals appear together:

* Unusual execution time
* Office application launching PowerShell
* PowerShell launching CMD
* CMD leading to `certutil.exe`
* A potentially suspicious LOLBin chain

However:

> **This is strong evidence for investigation, not automatic proof of compromise.**

I would investigate:

1. The user who opened the document.
2. The document/file that caused the execution.
3. Full PowerShell and CMD command lines.
4. `certutil.exe` command-line arguments.
5. Network connections.
6. Files created or downloaded.
7. Registry or persistence changes.
8. Other activity on the same endpoint.
9. Whether the behavior occurred on other endpoints.
10. Whether this is expected administrative or business activity.

---

# 🔥 Bonus — Office → Suspicious Process Hunter

```kql id="0y7i8v"
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "winword.exe",
    "excel.exe",
    "outlook.exe"
)
| where FileName in~ (
    "powershell.exe",
    "cmd.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe"
)
| project Timestamp,
          DeviceName,
          AccountName,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          FileName,
          ProcessCommandLine
```

### Hunting Logic

```text
Office Application
       ↓
Suspicious / Abused Windows Process
       ↓
Command Line
       ↓
User + Device
       ↓
Further Investigation
```

---

## 📚 KQL Concepts Learned

| Concept                        | Purpose                                           |
| ------------------------------ | ------------------------------------------------- |
| `InitiatingProcessFileName`    | Identifies the initiating/parent process          |
| `InitiatingProcessCommandLine` | Shows the parent's command line                   |
| `FileName`                     | Identifies the child process                      |
| `ProcessCommandLine`           | Shows the child's command line                    |
| `in~`                          | Case-insensitive matching against multiple values |
| `ago()`                        | Searches recent activity                          |
| `project`                      | Selects relevant investigation fields             |

---

## 🎯 Day 10 Key Takeaways

1. Process names alone don't provide enough investigation context.
2. Parent-child relationships reveal **how a process was launched**.
3. Office → PowerShell can be an important investigation lead.
4. Office → LOLBin relationships can provide additional context.
5. Multi-stage process chains can reveal attacker execution patterns.
6. The complete chain is more valuable than looking at a single event.
7. Unusual time + unusual parent + suspicious child + suspicious command line creates a stronger hunting lead.

### Today's mindset

```text
Day 08
"What process executed?"
        ↓
Day 09
"What did PowerShell execute?"
        ↓
Day 10
"What launched PowerShell?"
        ↓
Next
"Can I reconstruct the complete attack chain?"
```

---

## 📁 GitHub

**File:**

```text
day10_parent_child_process_hunting.md
```

**Commit:**

```text
Day 10: Parent-child process hunting
```

### Progress

```text
Day 01 ✅ KQL Basics
Day 02 ✅ Filtering
Day 03 ✅ String Hunting
Day 04 ✅ Calculated Fields
Day 05 ✅ Aggregation
Day 06 ✅ Time-Based Hunting
Day 07 ✅ Advanced Filtering
Day 08 ✅ Windows Process Hunting
Day 09 ✅ PowerShell Threat Hunting
Day 10 ✅ Parent-Child Process Hunting
```
