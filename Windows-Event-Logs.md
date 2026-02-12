# Windows Event Logging & Security Auditing Notes

## 1. Introduction to Windows Event Logs
Windows Event Logs are the central nervous system of Windows monitoring, acting as a comprehensive repository for recording system, security, and application activities.

* **Purpose**: Comprehensive logging for application errors, security auditing, intrusion detection, and diagnostics.
* **Format**: Logs are stored as **.evtx** files.
* **Access**:
    * **GUI**: Via the **Windows Event Viewer** (requires Administrative privileges).
    * **Programmatic**: Via APIs (e.g., Windows Event Log API).
    * **Offline Analysis**: You can open previously saved `.evtx` files from other machines in the "Saved Logs" section.

---

## 2. Log Categories
Windows organizes events into specific "Logs" based on their source:

| Log Name | Description |
| :--- | :--- |
| **Application** | Errors and status updates from installed programs and software. |
| **System** | Logs from Windows system components (drivers, boot sequence, etc.). |
| **Security** | Auditing events (logons, file access, privilege use). |
| **Setup** | Events related to the installation of applications and Windows updates. |
| **Forwarded Events** | A central repository for logs collected from *other* computers on the network. |

---

## 3. The Anatomy of an Event
Every log entry (Event) follows a standard structure. Understanding these fields is crucial for parsing data efficiently.

* **Log Name**: The container of the event (e.g., Application).
* **Source**: The software or component that generated the log.
* **Event ID**: A unique numeric identifier defining the specific type of event.
* **Level**: Severity classification (**Information**, **Warning**, **Error**, **Critical**, **Verbose**).
* **Keywords**: Broad "flags" for categorization (e.g., "Audit Success"). Useful for high-level filtering.
* **User**: The user account associated with the event (often "SYSTEM" or a specific username).
* **OpCode**: Identifies the specific operation being reported.
* **Computer**: The machine name where the event occurred.
* **XML Data**: The raw, structured format containing all visible fields plus hidden data.

---

## 4. Advanced Analysis Techniques

### A. Filtering with Keywords & XML
* **Keywords**: Use these to filter for broad outcomes (e.g., filtering Security log for "Audit Failure").
* **XML Queries**: Used for granular control via the "Filter Current Log" menu.
    * *Use Case*: Filter by `SubjectLogonId` (e.g., "0x3E7") to track a specific session across multiple events.

### B. Understanding Access Control (SDDL & ACLs)
To understand *why* a security log was generated, you must distinguish between permissions and auditing.
* **DACL (Discretionary Access Control List)**: Defines **Permissions** (Who is allowed/denied?).
* **SACL (System Access Control List)**: Defines **Auditing** (Who gets logged?).
* **NewSd / OldSd**: Found in logs like **Event ID 4907**. These fields show the Security Descriptor in **SDDL** format.

#### Deep Dive: Decoding SDDL Strings
An SDDL string is a text-based representation of security. Example: `S:ARAI(AU;SAFA;DCLCRPCRSDWDWO;;;WD)`

**1. The Header**
* **O:** Owner | **G:** Group | **D:** DACL | **S:** SACL
* **AR/AI**: Indicates if permissions are inherited or required for children.

**2. The ACE (Access Control Entry) Structure**
`([Type];[Flags];[Rights];[ObjectGUID];[InheritGUID];[Account])`



**3. Common Shorthand Codes**
| Code | Type/Permission | Account (Trustee) |
| :--- | :--- | :--- |
| **A / D** | Allow / Deny | **BA**: Built-in Admins |
| **AU** | Audit (SACL only) | **SY**: Local System |
| **GA / FA** | Full Control | **WD**: Everyone (World) |
| **SA / FA** | Success / Failure Audit | **AU**: Authenticated Users |

[Reference: Understanding SDDL Syntax - Microsoft Docs](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)

### C. Logon Analysis (Event 4624)
* **Logon ID**: A unique hex code (e.g., `0x3E7`) identifying a specific session.
* **Logon Type**: A numeric code explaining *how* the user logged in.
    * **Type 2**: Interactive (Keyboard/Screen).
    * **Type 3**: Network (Accessing a shared folder).
    * **Type 5**: Service (Background task startup).

[Reference: Event ID 4624 (Logon) Details - Microsoft Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)

---

## 5. Essential Windows Event IDs (Cheat Sheet)

### System Health & Status
| Event ID | Description | Significance |
| :--- | :--- | :--- |
| **1074** | System Shutdown/Restart | Detects unexpected reboots (malware or unauthorized access). |
| **7045** | New Service Installed | **High Priority.** Malware often installs itself for persistence. |

### Security & Intrusion Detection
| Event ID | Description | Significance |
| :--- | :--- | :--- |
| **1102** | Audit Log Cleared | **Critical.** Attacker trying to cover tracks. |
| **4625** | Failed Logon | Bursts indicate Brute-Force attacks. |
| **4719** | Audit Policy Changed | **Critical.** Attacker disabling logging to hide activity. |
| **4907** | Object's Audit Policy Changed | Shows changes to SACLs using SDDL strings. |

[Reference: Appendix L: Events to Monitor - Microsoft Docs](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)

---

## 6. Practice Decoding
**Example 1: Restricted Folder**
`D:(D;;FA;;;WD)(A;;GA;;;BA)`
* **Translation**: Everyone (**WD**) is **Denied** (**D**) all access (**FA**), while Admins (**BA**) are **Allowed** (**A**) Full Control (**GA**).

**Example 2: Audit Monitoring**
`S:(AU;FA;GR;;;WD)`
* **Translation**: Audit (**AU**) Everyone (**WD**) on **Failure** (**FA**) when they try to **Read** (**GR**) the object.

---

## 7. Best Practices for Professionals
1. **Know Your "Normal"**: You cannot spot anomalies if you don't know what normal traffic looks like.
2. **Centralize Logs**: Forward logs to a SIEM rather than checking individual machines.
3. **Correlate**: A single event is rarely enough. Combine data (e.g., *Failed Logon* + *New Service*).
