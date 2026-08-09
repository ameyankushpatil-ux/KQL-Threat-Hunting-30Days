# Day 01 — KQL Basics

## 🎯 Objective

Learn the fundamentals of **KQL (Kusto Query Language)** and understand how to retrieve and display security telemetry.

Today I learned:

* KQL tables
* `take`
* `project`
* Basic query pipelines
* Selecting relevant security telemetry for investigation

---

## 🧠 What is KQL?

**KQL = Kusto Query Language**

KQL is a query language used to search, analyze, and investigate large amounts of telemetry and log data.

Think of a KQL table like an **Excel sheet or database table**:

* **Table** → Dataset
* **Row** → Individual event
* **Column** → Attribute of the event

For example, `DeviceProcessEvents` contains endpoint process activity.

---

# 1. `take`

### What does `take` do?

`take` means:

> **"Give me some rows from this table."**

Example:

```kql
DeviceProcessEvents
| take 5
```

This query returns 5 records from the `DeviceProcessEvents` table.

### Why is this useful?

When investigating a large dataset, an analyst may first want to look at a small number of records to understand:

* What data is available?
* What columns exist?
* What type of events are being collected?

---

# 2. `project`

### What does `project` do?

`project` means:

> **"Show me only the columns I care about."**

Example:

```kql
DeviceProcessEvents
| project Timestamp, DeviceName, FileName
```

Instead of displaying every available column, we select only:

* `Timestamp`
* `DeviceName`
* `FileName`

This makes the investigation easier to read and reduces unnecessary information.

---

# 3. Combining `take` and `project`

We can combine operators using the KQL pipeline:

```kql
DeviceProcessEvents
| take 10
| project Timestamp, DeviceName, FileName
```

The query works from top to bottom:

```text
DeviceProcessEvents
        ↓
     take 10
        ↓
     project
        ↓
Relevant output
```

---

# 🧪 Day 1 Mission 1

### Scenario

The SOC manager asks:

> "I want to quickly see which processes are running on our endpoints. Show me the timestamp, device, user, and process name."

### Query

```kql
DeviceProcessEvents
| take 20
| project Timestamp, DeviceName, AccountName, FileName
```

### What this query provides

| Column        | Purpose                             |
| ------------- | ----------------------------------- |
| `Timestamp`   | When the event occurred             |
| `DeviceName`  | Endpoint where the process executed |
| `AccountName` | User associated with the activity   |
| `FileName`    | Process name                        |

---

# 🧪 Mission 2

### Scenario

The SOC manager originally requested 10 events, but now wants **20 events**.

### Query

```kql
DeviceProcessEvents
| take 20
| project Timestamp, DeviceName, AccountName, FileName
```

### Learning

The `take` value can be changed depending on how many records we want to initially examine.

---

# 🧪 Mission 3 — Analyst Thinking

### Question

Why would a SOC analyst use `project` instead of displaying every available column?

### Answer

If we don't use `project`, the query may return many unnecessary columns. During an investigation, this can create information overload and make it harder for the analyst to identify the relevant evidence.

Using `project` allows the analyst to focus on the fields that are important for the current investigation, making the investigation faster and easier to understand.

---

# ⭐ Bonus Challenge

### Objective

Display 15 process events with:

* Timestamp
* Device name
* Process name
* Process command line

### Query

```kql
DeviceProcessEvents
| take 15
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

---

# 🔍 SOC Analyst Perspective

Although these queries are simple, they introduce an important investigation concept:

> **Start broad enough to understand the telemetry, then reduce the data to the fields relevant to your investigation.**

A SOC analyst does not want to manually examine hundreds of irrelevant fields.

The goal is:

```text
Large telemetry dataset
        ↓
Understand the data
        ↓
Select relevant fields
        ↓
Investigate efficiently
```

---

# 📚 KQL Operators Learned

| Operator  | Purpose                                        |
| --------- | ---------------------------------------------- |
| `take`    | Returns a specified number of rows             |
| `project` | Selects specific columns                       |
| `\|`      | Passes the output of one operation to the next |

---

# 🎯 Day 1 Key Takeaways

1. KQL is used to query and analyze telemetry.
2. A KQL table contains rows and columns.
3. `take` is useful for quickly examining a sample of data.
4. `project` helps focus the investigation on relevant fields.
5. KQL operators are connected using the pipe `|`.
6. Good threat hunting starts with understanding the available telemetry.

---

## 🚀 Next Step

**Day 02 — Filtering with `where`**

We will move from:

> **"Show me some process events."**

to:

> **"Show me only suspicious or interesting process events."**

Topics:

* `where`
* `==`
* `!=`
* `contains`
* `has`
* `in`
* Case sensitivity
* First PowerShell hunting query

---

### GitHub Commit

```text
Day 01: KQL basics - take and project
```
