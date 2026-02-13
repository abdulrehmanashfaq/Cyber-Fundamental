## Event Tracing for Windows (ETW)

Traditional Windows logs give only a narrow view of what is happening on a system. **Event Tracing for Windows (ETW)** is a much richer telemetry framework built into the OS that can expose far more detail for threat detection, hunting, and incident response.

At a high level, ETW is a **high‑speed, kernel‑assisted tracing facility** that applications and drivers can use to publish events. Those events are picked up by trace sessions and stored or streamed for later analysis. Used correctly, ETW turns Windows into a continuous sensor for low‑level system behavior.

---

## 1. What is ETW?

Microsoft describes Event Tracing for Windows as a **general‑purpose, high‑performance tracing system**. It uses kernel‑level buffering and logging so that:

- **User‑mode applications** can emit events.
- **Kernel‑mode components and drivers** can do the same.

These events can cover:

- System calls
- Process and thread creation/termination
- Network connections
- File and registry operations
- And many other OS and application actions

Because ETW is built for performance, it can collect a **huge volume of fine‑grained telemetry** with relatively low overhead, making it suitable for **always‑on monitoring**.

### 1.1 Why ETW matters for defenders

Compared to classic event logs:

- ETW offers **deeper context** and more fields.
- Many **internal subsystems** expose ETW providers that never show up in standard Security / System logs.
- You can **target specific providers** to answer very narrow questions (e.g., PowerShell, .NET runtime, kernel process activity).

This makes ETW ideal for:

- Identifying subtle anomalies
- Correlating low‑level behavior across processes
- Supporting detailed forensics after an incident

---

## 2. ETW Architecture and Components

ETW follows a **publish–subscribe model**. Providers publish events; sessions collect them; consumers read and analyze them.

### 2.1 Controllers

**Controllers** manage trace sessions:

- Start and stop ETW sessions.
- Enable or disable specific providers for a session.
- Set buffer sizes, log locations, and other parameters.

The built‑in command‑line controller most analysts use is:

- `logman.exe` – creates, queries, and controls Event Tracing Sessions.

### 2.2 Providers

**Providers** are the sources of events. Applications, OS components, and drivers can all register as ETW providers.

ETW supports several provider types:

- **MOF providers**
  - Based on Managed Object Format (MOF) schemas.
  - Common in older or WMI‑style instrumentation.

- **WPP providers (Windows Software Trace Preprocessor)**
  - Use special macros/annotations in source code.
  - Often used for low‑level kernel tracing and debugging.

- **Manifest‑based providers**
  - Defined by XML manifest files describing event structure and fields.
  - Easier to manage and more self‑describing than MOF/WPP.

- **TraceLogging providers**
  - Use the TraceLogging API (newer Windows versions).
  - Offer a lightweight way to emit structured events with minimal code.

Each provider has:

- A **name** (e.g., `Microsoft-Windows-Winlogon`).
- A **GUID** (its unique identifier).
- Defined **keywords** and **levels** that control which events are emitted.

### 2.3 Consumers

**Consumers** subscribe to ETW sessions and process events. They can:

- Write events to **.ETL (Event Trace Log) files** on disk.
- Use the **Windows API** to process events in real‑time (e.g., for detection engines or telemetry collectors).

Examples of consumers:

- Built‑in Windows components (Event Log, Performance Monitor).
- EDR/AV agents.
- Custom tools or scripts using ETW APIs.

### 2.4 Channels

**Event channels** are logical groupings that control:

- Where events appear (which log in Event Viewer).
- How they are consumed (Operational vs Diagnostic vs Analytic, etc.).

Important notes:

- Only ETW events that have a **Channel property** can be exposed through the Windows Event Log interface.
- Consumers can subscribe to particular channels to narrow what they ingest.

### 2.5 ETL Files

ETW can log events to **ETL files**:

- Binary trace files optimized for performance and size.
- Support **rotation and retention policies**.
- Suitable for:
  - Offline analysis
  - Long‑term archiving
  - Post‑incident forensic work

---

## 3. Practical Interaction with ETW (logman)

`logman.exe` is a built‑in utility for inspecting and managing ETW sessions.

### 3.1 Listing Active Trace Sessions

To see which Event Tracing Sessions are currently running:

```text
C:\Tools> logman.exe query -ets
```

Key points:

- The `-ets` switch is critical – it tells `logman` to query **Event Tracing Sessions**, not only Performance Logs.
- The output lists each session, its **type** (trace), and **status** (running/stopped).
- You will often see:
  - Core OS sessions (e.g., `Circular Kernel Context Logger`).
  - EventLog‑backed sessions (e.g., `EventLog-System`, `EventLog-Application`).
  - Security‑relevant sessions (e.g., `EventLog-Microsoft-Windows-Sysmon-Operational`, `SYSMON TRACE`, `SysmonDnsEtwSession`).

### 3.2 Inspecting a Specific Session

To drill into the configuration of a single session:

```text
C:\Tools> logman.exe query "EventLog-System" -ets
```

This reveals:

- Session name and status.
- Log path and maximum size.
- Buffer sizes and flush timers.
- **List of subscribed providers**, each with:
  - Provider name and GUID.
  - **Level** (Error, Warning, Informational, etc.).
  - **KeywordsAny / KeywordsAll** used for filtering.

For incident responders, this is powerful:

- Finding a session that logs providers you care about may surface **crucial evidence**.
- You can see which providers are actively contributing to a log, and at what verbosity.

### 3.3 Enumerating All Providers

To list all providers registered on the system:

```text
C:\Tools> logman.exe query providers
```

This prints:

- Provider name.
- Provider GUID.

Windows 10 ships with **well over 1,000 built‑in providers**, and third‑party software commonly adds its own (especially kernel‑mode drivers, AV/EDR, VPN clients, etc.).

Because of the volume, you’ll usually filter with `findstr`:

```text
C:\Tools> logman.exe query providers | findstr "Winlogon"
```

### 3.4 Inspecting a Single Provider

Once you have a provider name, you can query its metadata:

```text
C:\Tools> logman.exe query providers Microsoft-Windows-Winlogon
```

This shows:

- Provider GUID.
- **Keywords**: Named bit flags describing event categories (e.g., `System`, `Telemetry`, `EventlogClassic`).
- **Levels**: Severity levels supported (Error, Warning, Informational).
- **Current PIDs** using the provider (if any).

For defenders, keywords and levels tell you:

- What kinds of events you can filter on.
- Which channels (`Operational`, `Diagnostic`, `System`) the provider feeds into.

---

## 4. GUI‑Based Options and Tools

While `logman` is powerful, there are graphical tools that can make ETW easier to explore.

### 4.1 Performance Monitor (Event Trace Sessions)

The **Performance Monitor** GUI can:

- Show **running Event Trace Sessions**.
- Let you double‑click a session to see:
  - Which providers it uses.
  - Whether it’s real‑time or file‑backed.
  - Buffer and file settings.
- Allow you to:
  - Create new user‑defined sessions.
  - Add or remove providers from a session.

This is useful when you want a quick visual overview of ETW activity on a host.

### 4.2 ETW Explorer

Projects like **EtwExplorer** provide a GUI to:

- Search for providers (e.g., providers containing "PowerShell").
- Inspect event metadata, fields, and channels for each provider.

These tools are very helpful when designing detection rules that depend on specific ETW fields.

---

## 5. High‑Value ETW Providers for Detection

There are thousands of providers; the list below highlights some that are particularly useful for security monitoring and hunting.

- **Microsoft-Windows-Kernel-Process**  
  Visibility into process lifecycle and related kernel activity. Helpful for spotting process injection, hollowing, and abnormal process chains.

- **Microsoft-Windows-Kernel-File**  
  Tracks file operations. Useful for detecting unauthorized file access, modification of critical binaries, and patterns associated with exfiltration or ransomware.

- **Microsoft-Windows-Kernel-Network**  
  Low‑level network telemetry. Good for identifying suspicious connections, unusual protocols, or potential C2 traffic.

- **Microsoft-Windows-SMBClient / Microsoft-Windows-SMBServer**  
  SMB activity on clients and servers. Valuable for detecting:
  - Lateral movement
  - Mass file access
  - Suspicious share enumeration or data staging

- **Microsoft-Windows-DotNETRuntime**  
  .NET runtime events. Ideal for spotting malicious .NET assembly loading, exploitation of .NET, or unexpected managed‑code usage.

- **OpenSSH**  
  SSH connection attempts, login successes/failures, and brute‑force indicators when OpenSSH is in use on Windows.

- **Microsoft-Windows-VPN-Client**  
  VPN session activity. Helps identify unauthorized or unusual VPN connections into or out of the environment.

- **Microsoft-Windows-PowerShell**  
  PowerShell operations and script execution. Critical for detecting:
  - Living‑off‑the‑land abuse
  - Malicious scripts
  - Suspicious interactive sessions

- **Microsoft-Windows-Kernel-Registry**  
  Registry changes. Useful for:
  - Persistence techniques
  - Service and autorun modifications
  - Malware configuration storage

- **Microsoft-Windows-CodeIntegrity**  
  Code and driver integrity checks. Helps catch unsigned / untrusted drivers or code injection attempts that violate integrity policies.

- **Microsoft-Antimalware-Service / Microsoft-Antimalware-Protection**  
  Telemetry from Defender or integrated antimalware components. Can reveal:
  - Tampering with protection
  - Service disable attempts
  - Evasion techniques

- **WinRM (Windows Remote Management)**  
  Remote management operations. Strong signal for:
  - Lateral movement via WinRM
  - Remote command execution

- **Microsoft-Windows-TerminalServices-LocalSessionManager**  
  Remote Desktop / Terminal Services session events. Useful for:
  - Detecting unauthorized RDP usage
  - Tracking logon/logoff patterns

- **Microsoft-Windows-Security-Mitigations**  
  Telemetry on exploit mitigations. Can highlight:
  - Attempts to bypass security controls
  - Crashes caused by mitigations blocking an attack

- **Microsoft-Windows-DNS-Client**  
  DNS activity on the client. Crucial for:
  - DNS tunneling detection
  - Suspicious or algorithmically generated domains
  - C2 infrastructure discovery

---

## 6. Restricted / High‑Privilege Providers

Some ETW providers expose **sensitive security telemetry** and are therefore restricted to privileged processes.

### 6.1 Microsoft-Windows-Threat-Intelligence

One notable example is **`Microsoft-Windows-Threat-Intelligence`**:

- Used heavily in DFIR and advanced detection scenarios.
- Captures highly granular threat‑related data.
- Access is typically limited to processes running as **Protected Process Light (PPL)**.

To run as a PPL, an anti‑malware vendor must:

- Work with Microsoft to obtain special signing and approvals.
- Implement an **ELAM (Early Launch Anti‑Malware)** driver.
- Pass validation and receive a privileged Authenticode signature.

Because of this, ordinary tools cannot simply subscribe to the Threat‑Intelligence provider. However, research has shown there are **workarounds and tradecraft** that can sometimes access this telemetry indirectly.

From a defender’s perspective, the value of this provider is significant:

- Detailed insight into threats that might not appear in higher‑level logs.
- Evidence about:
  - Where an attack originated.
  - Which assets were touched.
  - What changes were made.
- Potential for **near real‑time alerting** when monitored by security products that have access.

---

## 7. Summary and Next Steps

Event Tracing for Windows is a **core building block** for advanced Windows detection and response:

- It offers **deeper, broader telemetry** than traditional logs.
- Its **provider / session / consumer** model lets you tailor what you collect.
- With tools like `logman`, Performance Monitor, and ETW Explorer, defenders can discover and exploit high‑value providers for hunting.

In practice, ETW complements Sysmon and classic Security logs. In later analysis, you can use ETW‑only signals to catch attacks that **would not show up in Sysmon or standard Event Logs alone**, closing important visibility gaps in your monitoring stack.

