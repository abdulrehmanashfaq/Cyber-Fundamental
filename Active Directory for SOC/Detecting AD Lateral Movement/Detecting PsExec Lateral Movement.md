# Detecting PsExec Lateral Movement

PsExec is a legitimate remote administration tool. Attackers can use it with stolen administrative credentials to execute commands on another machine. The distinction from simple SMB share access is the **remote service and resulting execution**.

### How It Works

```text
Source process → SMB ADMIN$ → service binary written on destination
                                  ↓
                           Service installation (7045)
                                  ↓
                           Remote command execution (Sysmon 1)
                                  ↓
                           Named-pipe communication (Sysmon 17/18)
```

Default artifacts include `PSEXESVC` and `%SystemRoot%\PSEXESVC.exe`. Service names and binaries can be changed; other PsExec-style implementations use different defaults.

### 1. Destination: New Service

```splunk
index=win EventCode=7045
| table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
| sort _time
```

Event **7045 is in the System log**. Collect that channel as well as Security. A new demand-start service can be worth examining, but many legitimate services share that configuration.

The service account and the user context of the executed command are separate details. PsExec's `-s` requests SYSTEM for the command; inspect actual process telemetry rather than inferring command privileges from the service event alone.

### 2. Destination: Executed Commands

```splunk
index=win EventCode=1 host="{DESTINATION_HOST}" ParentImage="*PSEXESVC*"
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
```

Follow descendants as well as direct children. If the service was renamed, pivot to the actual binary path and process identifiers found in the service and process records.

### 3. Named Pipes

```splunk
index=win EventCode=17 Image="*PSEXESVC*"
| table _time, host, Image, PipeName
| sort _time
```

The default pipe names can include a source hostname, process identifier, and stdin/stdout/stderr suffixes. Naming is useful context, not a universal signature. Sysmon pipe events must be included by the configuration.

### 4. Trace the Remote Source With Detailed Share Events

```splunk
index=win EventCode=5145 host="{DESTINATION_HOST}" Relative_Target_Name="*PSEXE*"
| table _time, host, user, Source_Address, Share_Name, Relative_Target_Name
| sort _time
```

Event 5145 records a share access check for an object. Inspect its outcome, resource, source and account; it does not independently prove execution. Default-name searches can miss renamed tools.

### 5. Source Process

```splunk
index=win EventCode=1 host="{SOURCE_HOST}" Image="*PsExec*"
| table _time, host, User, Image, CommandLine
| sort _time
```

Correlate the target argument and time with the destination's share, service and process events. For renamed tools, investigate the same behavior chain without relying solely on the filename.

### Normal vs Suspicious

| Context | Expected administration | Investigate |
| --- | --- | --- |
| Source | Approved admin workstation | Unusual employee workstation |
| Account | Authorized administrator | Stolen or unexpected privileged identity |
| Target | Planned maintenance scope | Many hosts in a short period |
| Command | Approved maintenance | Discovery, payload launch, disabling controls |

**Audit prerequisites:** File Share auditing for 5140, Detailed File Share auditing for 5145, System collection for 7045, and configured Sysmon for process and pipe telemetry.

Source: [TryHackMe — Detecting AD Lateral Movement, Task 5](https://tryhackme.com/room/detectingadlateralmovement). Rewritten notes with supplementary interpretation caveats.
