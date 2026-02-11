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

### B. Understanding Access Control (SACLs)
To understand *why* a security log was generated, you must distinguish between permissions and auditing.
* **DACL (Discretionary Access Control List)**: Defines **Permissions** (Who is allowed/denied?).
* **SACL (System Access Control List)**: Defines **Auditing** (Who gets logged?).
* **NewSd / OldSd**: Found in logs like Event ID 4907. These fields show the Security Descriptor *before* and *after* a change.
* **uderstand more here https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists

### C. Logon Analysis (Event 4624)
* **Logon ID**: A unique hex code (e.g., `0x3E7`) identifying a specific session.
* **Logon Type**: A numeric code explaining *how* the user logged in.
    * **Type 2**: Interactive (Keyboard/Screen).
    * **Type 3**: Network (Accessing a shared folder).
    * **Type 5**: Service (Background task startup).

---

## 5. Essential Windows Event IDs (Cheat Sheet)

### System Health & Status
| Event ID | Description | Significance |
| :--- | :--- | :--- |
| **1074** | System Shutdown/Restart | Detects unexpected reboots (malware or unauthorized access). |
| **6005** | Event Log Service Started | Indicates system boot-up. |
| **6006** | Event Log Service Stopped | Indicates system shutdown. Unexpected stops are suspicious. |
| **6013** | System Uptime | Logged once daily. Short uptime implies a recent reboot. |
| **7040** | Service Status Change | Detects if critical services are disabled. |
| **7045** | New Service Installed | **High Priority.** Malware often installs itself as a service for persistence. |

### Security & Intrusion Detection
| Event ID | Description | Significance |
| :--- | :--- | :--- |
| **1102** | Audit Log Cleared | **Critical.** Often indicates an attacker trying to cover tracks. |
| **4624** | Successful Logon | Baselines normal user behavior (time, location). |
| **4625** | Failed Logon | Bursts of these indicate Brute-Force attacks. |
| **4648** | Logon with Explicit Creds | Potential lateral movement (attacker using stolen creds). |
| **4672** | Special Privileges Assigned | Indicates a "Super User" / Admin logon. Watch for abuse. |
| **4719** | Audit Policy Changed | **Critical.** Attacker disabling logging to hide activity. |
| **4738** | User Account Changed | Detects privilege escalation or account takeover. |
| **4771** | Kerberos Pre-Auth Failed | Similar to 4625 but for Kerberos; indicates brute-force attempts. |
| **5140** | Network Share Accessed | Detects unauthorized mapping/access of network drives. |

### Defender / Antivirus
| Event ID | Description | Significance |
| :--- | :--- | :--- |
| **1116** | Malware Detected | Defender found a threat. |
| **1118** | Remediation Started | Defender is trying to remove the threat. |
| **1119** | Remediation Success | The threat was neutralized. |
| **1120** | Remediation Failed | **Action Required.** The malware persists despite AV attempts. |
| **5001** | Real-time Protection Changed | Detects attempts to disable Antivirus protection. |

---

## 6. Best Practices for Professionals
1. **Know Your "Normal"**: You cannot spot anomalies (threats) if you don't know what normal traffic looks like.
2. **Centralize Logs**: Forward logs (using "Forwarded Events" or a SIEM) to a central server rather than checking individual machines.
3. **Correlate**: A single event is rarely a smoking gun. Combine data (e.g., *Failed Logon* + *Service Installed* + *Outbound Connection*).
4. **Monitor "Silence"**: The absence of logs (e.g., gaps in uptime or stopped logging services) is often as important as the logs themselves.
## 7. Useful References & Official Documentation
* [Microsoft Security Auditing Overview](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
* [Event ID 4624 (Logon) Details](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
* [Understanding SDDL Syntax](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format)
* [Appendix L: Events to Monitor](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor)
