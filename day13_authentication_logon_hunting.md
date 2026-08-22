# Day 13 — KQL Authentication & Sign-in Hunting

## 🎯 Objective

Use KQL to investigate **Windows authentication and logon activity**.

Today I practiced:

* Recent logon hunting
* Remote logon investigation
* Failed authentication analysis
* Authentication frequency
* Account + source IP analysis
* Account movement across multiple devices
* Remote authentication hunting

---

## 1. Basic Logon Hunting

`DeviceLogonEvents` provides endpoint logon/authentication telemetry.

### Mission 1

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| project Timestamp,
          DeviceName,
          AccountName,
          LogonType,
          ActionType
```

This gives a basic view of recent authentication activity.

---

## 2. Remote Logon Hunting

`LogonType` helps identify how an account authenticated.

Remote interactive authentication can be particularly useful during investigations because it can provide evidence of remote access.

### Mission 2

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType =~ "RemoteInteractive"
| project Timestamp,
          DeviceName,
          AccountName,
          LogonType,
          ActionType,
          RemoteIP,
          RemoteDeviceName
---

## 3. Failed / Non-Successful Logons

Authentication failures can be useful when investigating:

* Brute-force attempts
* Password spraying
* Misconfigured applications
* Expired credentials
* Legitimate user mistakes

A failed authentication event does **not automatically indicate an attack**.

### Mission 3

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType != "LogonSuccess"
| project Timestamp,
          DeviceName,
          AccountName,
          LogonType,
          ActionType,
          RemoteIP
```

> **Note:** `ActionType` values can vary depending on the telemetry available in your environment. Always validate the values present in your dataset before building production detections.

---

## 4. Failed Authentication by Account

Now combine authentication filtering with `summarize`.

### Mission 4

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType != "LogonSuccess"
| summarize Count = count() by AccountName
| order by Count desc
```

This helps identify accounts generating the highest number of non-successful logon events.

### SOC Perspective

A high failure count can be interesting, but investigate the context:

```text
Account
   ↓
Source IP
   ↓
Target Device
   ↓
Time
   ↓
Failure Pattern
```

---

## 5. Account + Remote IP

### Mission 5

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where ActionType != "LogonSuccess"
| summarize Count = count() by AccountName, RemoteIP
| order by Count desc
```

This helps answer:

> **"Which accounts are receiving non-successful authentication attempts from which source IPs?"**

A repeated account/IP combination can help identify potential password-spraying or brute-force patterns, but should be validated against normal activity.

---

## 6. Account Across Multiple Devices

An account appearing on many devices can be completely legitimate, especially for administrators or service accounts.

However, unexpected account movement can be an important investigation signal.

### Mission 6

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| summarize DeviceCount = dcount(DeviceName) by AccountName
| order by DeviceCount desc
```

`dcount()` returns the approximate number of **unique values**.

Here it answers:

> **"How many different devices did each account authenticate to?"**

---

## 🔥 7. Remote Authentication Hunter

Combine remote authentication with account, source IP, and destination device.

### Mission 7

```kql
DeviceLogonEvents
| where Timestamp > ago(24h)
| where LogonType =~ "RemoteInteractive"
| summarize Count = count() by AccountName, RemoteIP, DeviceName
| order by Count desc
```

### Improvement

The original query called the result:

```text
DeviceCount
```

but `count()` counts **events**, not unique devices.

Therefore:

```text
Count = count()
```

is more accurate.

If we wanted the number of unique devices, we would use:

```kql
dcount(DeviceName)
```

---

# 🧠 Analyst Challenge

Suppose you find:

```text
Account: john

RemoteIP: 10.10.20.55

PC-01
PC-02
PC-05
PC-07
PC-11
PC-15
```

within a short period.

This does **not automatically mean compromise**.

I would investigate:

1. Is `john` an administrator?
2. Is `10.10.20.55` a known corporate device?
3. Is this normal for the user's role?
4. What time did the activity occur?
5. Were there failed logons before successful authentication?
6. Were multiple devices accessed unusually quickly?
7. What processes executed after authentication?
8. Was persistence created?
9. Were sensitive resources accessed?
10. Is the source IP associated with other suspicious accounts?

---

# 🔗 Connecting Days 12 + 13

Day 12 showed:

```text
Account
   ↓
Process
   ↓
PowerShell
```

Day 13 adds:

```text
Account
   ↓
Authentication
   ↓
Source IP
   ↓
Destination Device
```

Together:

```text
Authentication
      ↓
Account
      ↓
Device
      ↓
Process
      ↓
PowerShell / LOLBin
      ↓
Persistence
```

This is how an analyst begins building an **attack timeline** instead of investigating isolated alerts.

---

## 📚 KQL Concepts Learned

| KQL                 | Purpose                                  |
| ------------------- | ---------------------------------------- |
| `DeviceLogonEvents` | Logon/authentication telemetry           |
| `LogonType`         | Identifies the authentication type       |
| `ActionType`        | Describes the logon event/action         |
| `RemoteIP`          | Source IP associated with the event      |
| `RemoteDeviceName`  | Remote device information when available |
| `dcount()`          | Counts unique values                     |
| `summarize`         | Aggregates events                        |
| `count()`           | Counts events                            |
| `ago()`             | Searches recent activity                 |
| `=~`                | Case-insensitive comparison              |
| `project`           | Selects relevant fields                  |

---

## 🎯 Day 13 Key Takeaways

1. Authentication activity provides important identity context.
2. `LogonType` helps identify how an account accessed a system.
3. Failed logons can reveal brute-force or password-spraying patterns.
4. `AccountName + RemoteIP` can help identify suspicious authentication sources.
5. `dcount(DeviceName)` can identify accounts accessing multiple endpoints.
6. High authentication volume does not automatically indicate compromise.
7. Authentication should be correlated with **process, network, and persistence telemetry**.
