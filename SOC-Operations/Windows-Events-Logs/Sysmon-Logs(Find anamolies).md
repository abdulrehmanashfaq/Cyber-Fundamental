## Sysmon and Windows Event Logs

Effective blue‑team work depends on being able to recognize **malicious patterns** hidden among millions of benign events. This note builds on basic Windows logging and focuses on **how to use Sysmon plus native Event Logs to hunt for real attacks**, with three concrete detection examples.

---

## 1. Sysmon Basics for Detection Engineering

Sysmon (System Monitor) is a Windows system service and driver that stays resident across reboots and writes detailed telemetry into the Windows Event Log.

- **Core components**
  - **Windows service**: Monitors system activity.
  - **Device driver**: Captures low‑level system activity.
  - **Event log**: Exposes captured data under `Applications and Services Logs → Microsoft → Windows → Sysmon`.

- **Why Sysmon matters**
  - Logs **process creation**, **network connections**, **image (DLL) loads**, file timestamps, and more.
  - Provides visibility that **does not exist** in standard Security logs.

- **Key Event IDs**
  - **Security 4624**: Successful logon (classic Windows Event Log).
  - **Security 4688**: New process creation.
  - **Sysmon 1**: Process creation.
  - **Sysmon 3**: Network connection.
  - **Sysmon 7**: Image (DLL) load.
  - **Sysmon 10**: Process access.

### 1.1 Sysmon Configuration

Sysmon is driven by an **XML configuration** that decides what to log or ignore.

- **Popular configurations**
  - Comprehensive config (used here): `SwiftOnSecurity/sysmon-config`.
  - Modular config: `olafhartong/sysmon-modular`.

- **Include vs Exclude**
  - `include`: Only events matching the rules are logged.
  - `exclude`: Everything is logged **except** what matches the rules.

This makes the difference between **quiet, high‑signal logs** and **noisy, useless telemetry**.

### 1.2 Installing Sysmon (Windows)

1. Download Sysmon from the official Sysinternals page.  
2. Open an elevated Command Prompt and install:

```text
C:\Tools\Sysmon> sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n
```

3. To apply or update a custom configuration:

```text
C:\Tools\Sysmon> sysmon.exe -c sysmonconfig-export.xml
```

> Note: **Sysmon for Linux** also exists, with similar concepts but different event fields.

---

## 2. Detection Example 1 – DLL Hijacking (Sysmon Event ID 7)

### 2.1 Attack Concept

**DLL hijacking** abuses how Windows searches for DLLs. If an attacker can drop a malicious DLL where a trusted binary will load it (e.g., writable folder before `System32` in the search path), they can run arbitrary code under that trusted process.

Target in this example:

- Executable: `calc.exe`  
- Hijacked DLL: `WININET.dll`

### 2.2 Sysmon Configuration for DLL Loads

To monitor DLL hijacks, we care about **Sysmon Event ID 7 – ImageLoad**.

- In the `sysmonconfig-export.xml`:
  - The `ImageLoad` rule group controls DLL loading visibility.
  - If `ImageLoad` is set to `include` with no rules, **nothing is logged**.
  - For broad hunting, change it to `exclude` with no rules, so **no DLL loads are excluded**, and you log everything.

Once updated:

```text
C:\Tools\Sysmon> sysmon.exe -c sysmonconfig-export.xml
```

Then, DLL load telemetry will appear under:

> `Event Viewer → Applications and Services Logs → Microsoft → Windows → Sysmon`

### 2.3 Reading Event ID 7 for DLL Hijacks

A normal Event ID 7 example:

- **Image**: `mmc.exe`  
- **ImageLoaded**: `psapi.dll`  
- **Signed**: `true` (Microsoft)  
- **Location**: `C:\Windows\System32\...`  
- **User**: legitimate user (e.g., `DESKTOP\Waldo`)

For the hijack:

- The attacker:
  - Copies `calc.exe` out of `C:\Windows\System32\` to a **writable folder** (e.g., Desktop).
  - Renames a malicious DLL (e.g., a reflective DLL renamed to `WININET.dll`).
  - Runs `calc.exe` from that writable folder.

In Sysmon Event ID 7, you then see:

- **Image**: `C:\Users\Waldo\Desktop\calc.exe`
- **ImageLoaded**: `C:\Users\Waldo\Desktop\WININET.dll`
- **Signed**: `false`

Compared to a legitimate case:

- **Image**: `C:\Windows\System32\calc.exe`
- **ImageLoaded**: `C:\Windows\System32\wininet.dll`
- **Signed**: `true` (Microsoft)

### 2.4 Practical IOCs for DLL Hijack (calc.exe)

- **IOC 1 – System binary in a writable location**
  - `calc.exe` should live in `System32` / `SysWOW64`, **not** user‑writable folders.

- **IOC 2 – System DLL loaded from the wrong directory**
  - `WININET.dll` loaded from Desktop or another writable path by `calc.exe` instead of `System32`.

- **IOC 3 – Signature mismatch**
  - Legit `WININET.dll` is **Microsoft‑signed**.
  - Hijacked `WININET.dll` is **unsigned or differently signed**.

Combined, these three IOCs give a high‑confidence detection for this specific DLL hijack.

---

## 3. Detection Example 2 – Unmanaged PowerShell / C# Injection

### 3.1 Background: Managed Code and the CLR

- **C#** is a **managed** language:
  - Code is compiled into **bytecode** (MSIL).
  - The **Common Language Runtime (CLR)** executes this bytecode.
- A **managed process** loads CLR components such as:
  - `clr.dll`
  - `clrjit.dll`

For defenders, this means:

- A process that normally has **no reason** to run .NET/C# but suddenly loads `clr.dll`/`clrjit.dll` is a strong sign of:
  - **Execute‑assembly abuse**
  - **Unmanaged PowerShell injection**
  - **In‑memory C# tradecraft**

### 3.2 Using Process Hacker for Visual Verification

Tools like **Process Hacker** make this pattern obvious:

- `powershell.exe` is highlighted as a **managed (.NET)** process.
- Its **Modules** tab shows `clr.dll` and `clrjit.dll` loaded from Microsoft .NET runtime.

If a normally unmanaged process (e.g., `spoolsv.exe`) suddenly:

- Becomes "managed (.NET)" in Process Hacker, **and**
- Shows `clr.dll` / `clrjit.dll` among its loaded modules,

…then something has injected C#/.NET into that process.

### 3.3 Unmanaged PowerShell Injection Example

Using a tool such as **PSInject**:

```powershell
powershell -ep bypass
Import-Module .\Invoke-PSInject.ps1
Invoke-PSInject -ProcId [spoolsv PID] -PoshCode "Write-Host 'Hello, Guru99!'"
```

Effect:

- `spoolsv.exe` (Print Spooler) transitions from unmanaged → **managed**.
- CLR‑related modules appear in its module list.

### 3.4 Sysmon View – Event ID 7 for CLR Loads

Sysmon Event ID 7 will show:

- **Image**: `spoolsv.exe`  
- **ImageLoaded**: `clr.dll` / `clrjit.dll`  
- **User**: Often `NT AUTHORITY\SYSTEM`

**High‑value IOC**:

- Non‑developer, non‑.NET host process
  - (e.g., services like `spoolsv.exe`, `lsass.exe`, `svchost.exe` in some contexts)
- **Loading CLR DLLs** (especially shortly before/after suspicious PowerShell usage)

This pattern is strong evidence of:

- Unmanaged PowerShell
- C# execute‑assembly frameworks
- Post‑exploitation frameworks abusing .NET

---

## 4. Detection Example 3 – Credential Dumping (LSASS / Mimikatz)

### 4.1 Attack Overview

Tools like **Mimikatz** can dump credentials by interacting with the **Local Security Authority Subsystem Service (LSASS)**.

Classic Mimikatz flow:

```text
C:\Tools\Mimikatz> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

The `sekurlsa::logonpasswords` command extracts:

- Usernames, domains, SIDs
- NTLM / SHA1 hashes
- Sometimes plaintext passwords

All of this is sourced from **LSASS memory**, making LSASS a prime target.

### 4.2 Sysmon Event ID 10 – ProcessAccess

To detect credential dumping, we focus on:

- **Sysmon Event ID 10 – ProcessAccess**
  - Logs one process **accessing another process** (e.g., suspicious EXE opening LSASS).

Sample malicious pattern:

- **SourceImage**: `C:\Users\Waldo\Downloads\AgentEXE.exe`
- **TargetImage**: `C:\Windows\System32\lsass.exe`
- **SourceUser**: `DESKTOP\Waldo`
- **TargetUser**: `NT AUTHORITY\SYSTEM`

Red flags:

- Random or unsigned binary from user profile / `Downloads` / temp directories.
- Accessing **lsass.exe** via `ProcessAccess`.
- Source user ≠ target user (`waldo` vs `SYSTEM`).
- The tool requests **SeDebugPrivilege** (required by many dumpers).

### 4.3 Interpreting LSASS Access Telemetry

Not all LSASS access is malicious. Normal access may come from:

- Authentication components.
- Security tools (AV/EDR).

However, the following is suspicious and usually worth alerting on:

- Non‑signed or unknown binary.
- Located in user‑writable paths.
- Rarely/never seen in environment baselines.
- Suddenly starts reading LSASS memory (Sysmon Event 10).

Combined with Mimikatz‑like behavior, this is a strong IOC for **credential dumping**.

---

## 5. Summary: Turning Telemetry into Detections

Using Sysmon and Windows Event Logs, defenders can build **high‑fidelity detections** by combining:

- **Where** something runs (path: `System32` vs Desktop/Downloads).
- **What** modules it loads (e.g., unsigned `WININET.dll`, unexpected `clr.dll`).
- **Which** processes it touches (e.g., `lsass.exe` for credential dumping).
- **Who** runs it (user vs `SYSTEM`, privilege escalation patterns).

These patterns form **portable detection rules** (for SIEM, EDR, Sigma, or KQL) that reliably distinguish **“evil”** from the background noise of normal Windows activity.

