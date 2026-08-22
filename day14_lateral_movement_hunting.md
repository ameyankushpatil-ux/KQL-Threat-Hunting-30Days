# Day 14 — KQL Lateral Movement Hunting

## 🎯 Objective

Learn how to use KQL to identify **remote authentication and potential lateral movement** across Windows endpoints.

Today I practiced:

* RDP hunting
* Remote interactive logons
* Network logons
* Account → multiple devices
* Remote IP → multiple accounts
* PsExec hunting
* Lateral movement investigation
* Attack-chain thinking

---

## 1. What is Lateral Movement?

**Lateral movement** is when an attacker moves from one compromised system to another system inside an environment.

A simplified attack path:

```text
Compromised PC
      ↓
Stolen credentials
      ↓
Remote authentication
      ↓
Another endpoint
      ↓
Command execution
```

Common Windows lateral-movement techniques include:

```text
Remote Desktop (RDP)
SMB / Windows Admin Shares
PsExec
WinRM
Remote Services
WMI
```

> Remote access by itself is not malicious. The analyst must determine whether the account, source, destination, timing, and subsequent activity are expected.

---

## 2. RDP Hunting

RDP commonly generates:

```text
LogonType = RemoteInteractive
```

### Mission 1 — Successful RDP Activity

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType =~ "RemoteInteractive"
| where ActionType == "LogonSuccess"
| project Timestamp,
          DeviceName,
          AccountName,
          LogonType,
          ActionType,
          RemoteIP,
          RemoteDeviceName
```

### Corrections

The original query used:

```text
RemoteInteraction
```

The correct value is:

```text
RemoteInteractive
```

Also, KQL equality uses:

```text
==
```

not:

```text
=
```

---

## 3. Top RDP Users

### Mission 2

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType =~ "RemoteInteractive"
| where ActionType == "LogonSuccess"
| summarize Count = count() by AccountName
| order by Count desc
```

This identifies accounts generating the highest number of successful remote interactive logons.

---

## 4. Account → Multiple Devices

An account accessing many endpoints can be legitimate, especially for administrators.

However, unexpected access to multiple systems can become an important investigation signal.

### Mission 3

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType =~ "RemoteInteractive"
| where ActionType == "LogonSuccess"
| summarize DeviceCount = dcount(DeviceName) by AccountName
| order by DeviceCount desc
```

This answers:

> **How many unique devices did each account access through remote interactive logons?**

---

## 5. Remote IP → Multiple Accounts

Instead of looking at:

```text
Account → Devices
```

we can reverse the investigation:

```text
Remote IP → Accounts
```

### Mission 4

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType =~ "RemoteInteractive"
| where ActionType == "LogonSuccess"
| summarize AccountCount = dcount(AccountName) by RemoteIP
| order by AccountCount desc
```

This can help identify a source IP authenticating as multiple accounts.

Possible explanations include:

* Administrator/jump server activity
* Shared infrastructure
* Automated management
* Credential reuse
* Compromised source system

---

## 6. Network Logon Hunting

`Network` logons can provide additional authentication context, particularly around network resource access.

### Mission 5

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType =~ "Network"
| project Timestamp,
          DeviceName,
          AccountName,
          LogonType,
          ActionType,
          RemoteIP
```

The analyst should investigate whether the account and source IP are expected.

---

# 7. PsExec Hunting

PsExec is commonly associated with remote administration and can also be abused for lateral movement.

### Important

PsExec activity may not always appear as a process named exactly:

```text
psexec.exe
```

depending on the execution method and available telemetry.

### Mission 6 — PsExec

`DeviceLogonEvents` is not the appropriate table for process fields such as `FileName` and `ProcessCommandLine`.

Use `DeviceProcessEvents`:

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "psexec.exe"
| project Timestamp,
          DeviceName,
          AccountName,
          FileName,
          ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine
```

This allows us to investigate:

```text
User
 ↓
PsExec
 ↓
Command Line
 ↓
Parent Process
```

---

# 🔥 8. Mission 7 — Lateral Movement Investigation

The original Mission 7 attempted to calculate:

```text
dcount(FileName)
```

from `DeviceLogonEvents`.

That does not work because `FileName` is a process field and belongs to process telemetry.

A better **first-stage lateral movement hunter** is:

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType =~ "RemoteInteractive"
| where ActionType == "LogonSuccess"
| summarize Count = count() by AccountName, RemoteIP, DeviceName
| order by Count desc
```

This produces:

```text
Account
   ↓
Source IP
   ↓
Destination Device
   ↓
Number of remote logons
```

Then correlate interesting results with `DeviceProcessEvents` to determine whether suspicious processes executed after authentication.

---

# 🧠 Analyst Challenge

Scenario:

```text
10:00 PM

RemoteIP: 10.10.20.55
Account: john

       ↓

PC-01
PC-02
PC-03
PC-04

       ↓

powershell.exe
       ↓
cmd.exe
```

### Investigation Checklist

I would investigate:

* Is `john` an administrator?
* Is `10.10.20.55` a known jump server?
* Is this normal for the user's role?
* Were there failed logons before successful logons?
* What happened immediately after authentication?
* Was PowerShell executed remotely?
* Were credentials reused across multiple systems?
* Was persistence created?
* Did the source machine show signs of compromise?
* Were other accounts accessed from the same source?

### Key Lesson

This activity is **suspicious enough to investigate**, but the evidence should be correlated before declaring a compromise.

---

# 🔗 Building an Attack Timeline

Day 14 connects several previous skills:

```text
Authentication
      ↓
Account
      ↓
Remote IP
      ↓
Destination Device
      ↓
Process Execution
      ↓
PowerShell / CMD / LOLBin
      ↓
Persistence
```

This is how an analyst moves from individual alerts toward reconstructing a potential **lateral-movement attack chain**.

---

## 📚 KQL Concepts Learned

| KQL / Concept         | Purpose                     |
| --------------------- | --------------------------- |
| `DeviceLogonEvents`   | Authentication telemetry    |
| `DeviceProcessEvents` | Process execution telemetry |
| `RemoteInteractive`   | Remote interactive logon    |
| `Network`             | Network logon type          |
| `RemoteIP`            | Source IP                   |
| `RemoteDeviceName`    | Remote source device        |
| `dcount()`            | Count unique values         |
| `summarize`           | Aggregate events            |
| `==`                  | Exact equality              |
| `=~`                  | Case-insensitive equality   |
| `ago()`               | Relative time filtering     |

---

## 🎯 Day 14 Key Takeaways

1. Lateral movement involves moving from one system to another.
2. RDP activity can be investigated using `RemoteInteractive` logons.
3. `AccountName + RemoteIP + DeviceName` provides useful movement context.
4. An account accessing many systems isn't automatically malicious.
5. PsExec should be hunted using process telemetry, not logon telemetry.
6. Authentication and process telemetry should be correlated.
7. The source system, account, destination, timing, and subsequent execution all matter.
