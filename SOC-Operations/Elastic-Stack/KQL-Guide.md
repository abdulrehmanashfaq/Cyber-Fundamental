# Kibana Query Language (KQL) Mastery Guide

## 1. Overview
**KQL (Kibana Query Language)** is a syntax specifically designed for filtering data in Kibana. It is distinct from the Lucene Query Syntax and Elasticsearch Query DSL, offering a simpler, more intuitive experience for SOC analysts.

## 2. Search Modalities

### Free Text Search
Searching for a string without specifying a field.
* **Syntax:** `"svc-sql1"`
* **Behavior:** Kibana scans *every* field in the index for this string.
* **Pros/Cons:** Easy to use, but inefficient on large datasets and prone to false positives.

### Field-Level Search
Searching for a value within a specific field.
* **Syntax:** `field:value` (e.g., `event.code:4625`)
* **Behavior:** Checks only the specified field.
* **Pros/Cons:** Highly efficient and precise. This is the professional standard for creating alerts.

## 3. Logical Operators
KQL uses standard boolean logic to construct complex queries.

| Operator | Function | Example | Explanation |
| :--- | :--- | :--- | :--- |
| **AND** | Intersection | `event.code:4625 AND user.name:admin` | Finds events where BOTH conditions are true. |
| **OR** | Union | `event.code:4625 OR event.code:4624` | Finds events where EITHER condition is true. |
| **NOT** | Exclusion | `NOT status:success` | Excludes events where the status is success. |

**Grouping:** Parentheses `()` determine the order of operations.
* `event.code:4625 AND (user.name:admin OR user.name:root)`
    * *Logic:* Find failed logins, BUT only for the "admin" OR "root" users.

## 4. Advanced Pattern Matching

### Wildcards
* **Syntax:** `*`
* **Usage:** Matches any character sequence.
    * `user.name: admin*` matches "admin", "administrator", "admin_backup".
    * `process.name: *.exe` matches any executable file.

### Range Queries (Time & Numbers)
Crucial for establishing a timeline of an attack.
* **Operators:** `:`, `>`, `>=`, `<`, `<=`
* **Time Example:** `@timestamp > "2025-01-01" AND @timestamp < "2025-01-02"`
* **Numeric Example:** `source.bytes >= 1000000` (Finds large data transfers).



---
