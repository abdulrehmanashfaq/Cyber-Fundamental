# Detecting Web Shell Deployment

A **web shell** is a server-side script that allows an attacker to run commands through web requests. In an IIS environment, an unexpected `.aspx` file can provide this access. Its presence in a web directory is suspicious when it is unrelated to the application.

### How the Activity Appears

```text
Scanning → exploit/upload → shell.aspx requested → w3wp.exe → cmd.exe / PowerShell
```

The important process relationship is **IIS worker process `w3wp.exe` spawning command interpreters or reconnaissance tools**. A legitimate application can create child processes, including compiler processes, so investigate the command and application baseline before deciding it is malicious.

### Investigation in Splunk

Use `index=iis` for HTTP access and `index=win` for the room's Windows/Sysmon events. Restrict the time range and host as you pivot.

#### 1. Find scanning sources

```splunk
index=iis sc_status=404
| stats count by c_ip
| sort - count
```

A high count is a lead. Check timing, requested paths, and whether the source is an approved scanner.

#### 2. Find what the source successfully accessed

```splunk
index=iis c_ip="{SUSPICIOUS_IP}" sc_status=200
| stats count by cs_uri_stem
| sort - count
```

An unfamiliar script under `/aspnet_client/` deserves attention. That directory normally holds ASP.NET client resources; whether IIS can write there depends on permissions.

#### 3. Inspect interaction with the script

```splunk
index=iis cs_uri_stem="*/{WEBSHELL_FILENAME}"
| table _time, c_ip, cs_method, cs_uri_query, sc_status
| sort _time
```

Look for commands in query parameters. Commands sent in a POST body may be absent from standard access logs, so an empty query string does not rule out a shell.

#### 4. Confirm execution on the endpoint

```splunk
index=win EventCode=1 ParentImage="*\\w3wp.exe"
| table _time, host, Image, ParentImage, CommandLine
| sort _time
```

Sysmon Event **1** records process creation. Security Event **4688** can provide an alternative if process creation and command-line auditing are enabled; its field names differ.

#### 5. Establish file creation time

```splunk
index=win EventCode=11 TargetFilename="*{WEBSHELL_FILENAME}"
| table _time, host, Image, TargetFilename
| sort _time
```

Sysmon Event **11** records file creation when included by the configuration. Compare the writer, filename, host, and timestamp with the HTTP timeline.

If the upload filename appeared in a URL parameter, this may reveal the upload request:

```splunk
index=iis cs_method=POST cs_uri_query="*{WEBSHELL_FILENAME}*"
| table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
| sort _time
```

**Warning:** This is a fallback lead, not a universal upload detector. Upload filenames can be present only in the request body. A 200 response alone does not prove file creation or command execution.

### Investigation Challenge Method

Start with the 404 source, follow its successful requests, identify the script and upload endpoint, then use process and file events to establish the first command and creation time. The challenge uses a separate dataset from the walkthrough. Record findings from that dataset rather than carrying over walkthrough answers.

Source: [TryHackMe — Detecting AD Initial Access, Tasks 3 and 8](https://tryhackme.com/room/detectingadinitialaccess). Queries follow the room with small presentation adjustments; caveats are supplementary.
