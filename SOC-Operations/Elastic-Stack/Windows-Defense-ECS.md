# Windows Event Monitoring & The Elastic Common Schema (ECS)

> Note: These ECS and Windows logging notes are written in my own words, drawing on official Elastic/Winlogbeat documentation and security training content (including Hack The Box) as learning sources.

## 1. The Elastic Common Schema (ECS)
**ECS** is an open source specification that defines a common set of document fields for data ingested into Elasticsearch.

### The Problem: Field Divergence
Without ECS, different devices name the same data differently:
* **Cisco Firewall:** `src_ip`
* **Windows:** `SourceAddress`
* **Apache Web Server:** `client_ip`

### The Solution: Normalization
ECS forces all these sources to map to a single field: `source.ip`.
* **Unified Search:** A query for `source.ip: 10.10.10.5` searches Firewalls, Windows servers, and Web servers simultaneously.
* **Correlation:** Allows analysts to track an attacker's lateral movement across different technology stacks.

## 2. Field Identification Strategies
To write effective KQL, you must know the field names.

* **Method A: The "Discover" Workflow**
    1.  Perform a Free Text Search for a known value (e.g., `"4625"`).
    2.  Expand the resulting document JSON.
    3.  Identify the mapped field name (e.g., observe that "4625" maps to `event.code`).

* **Method B: Documentation Reference**
    Always refer to the official **Winlogbeat ECS Fields** documentation.
    * `winlog.event_id` -> The native Windows ID.
    * `event.code` -> The ECS standard ID.

## 3. Threat Hunting Scenario: Windows Event 4625
**Event 4625** logs a failed login attempt. It is the primary indicator for Brute Force attacks.

### Critical Analysis Fields
When analyzing Event 4625, you must look at the `winlog.event_data.SubStatus` field to understand *why* the failure occurred.

| SubStatus Hex | Meaning | Security Implication |
| :--- | :--- | :--- |
| **0xC0000064** | User Name does not exist | Attacker is guessing usernames. |
| **0xC000006A** | Correct User, Wrong Password | Attacker has a valid username but is guessing passwords. |
| **0xC0000072** | **Account is Disabled** | **High Severity.** Attacker is using old/stolen credentials for an inactive employee. |
| **0xC0000234** | Account Locked Out | Brute force attempt has triggered the lockout policy. |

### The "Smoking Gun" Query
To find an attacker trying to use disabled accounts:
```kql
event.code:4625 AND winlog.event_data.SubStatus:0xC0000072
