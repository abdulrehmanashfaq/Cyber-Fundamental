# Detecting RDP Lateral Movement

RDP provides an interactive remote session. The main destination-side Security event is **4624 with Logon Type 10**. Start with suspicious activity on a target, identify its session, and work backwards to the source.

### Important Logon Details

| Type | Interpretation |
| --- | --- |
| 10 | RemoteInteractive, commonly RDP |
| 3 | Network authentication; can precede Type 10 with NLA |
| 7 | Unlock; inspect remote reconnection context |

**NLA (Network Level Authentication)** can produce a Type 3 before the interactive logon. That does not automatically mean a separate SMB connection occurred.

Reconnects may involve Type 7 and session continuity differences. Validate with Terminal Services operational logs and disconnect/reconnect events where collected; Type 7 alone does not prove an RDP connection. Logon IDs should be correlated on the **same host and within the relevant time/boot context**.

### 1. Start With Suspicious Commands on the Destination

```splunk
index=win EventCode=1 host="THM-DC"
| search CommandLine IN ("*nltest*","*net * user*","*net * group*","*net * view*")
| table _time, host, User, Image, CommandLine, LogonId
| sort _time
```

This is the room's illustrative discovery search; command spacing and alternative tools can change the match. Review the actual process and command line.

### 2. Find How That Session Was Established

```splunk
index=win EventCode=4624 host="THM-DC" Logon_ID="{LOGON_ID}"
| table _time, host, user, Logon_Type, Source_Network_Address, Logon_ID
| sort _time
```

Match Sysmon `LogonId` to the Security event's **target/new-logon ID**. Some parsers expose several IDs or use decimal instead of hexadecimal, so normalize before correlating.

### 3. Confirm Source Host and Outbound RDP

Resolve the source IP using time-appropriate asset, EDR, DHCP or DNS records. The room also uses machine-account logons as a hostname clue, but that requires independent confirmation.

```splunk
index=win EventCode=1 host="{SOURCE_SERVER}" Image="*mstsc.exe*"
| table _time, host, User, Image, CommandLine, LogonId
| sort _time
```

`mstsc.exe` is the Windows Remote Desktop client. Launching it indicates an attempt, not necessarily a completed connection. Other clients can also establish RDP.

### 4. Work Backwards Through the Chain

```splunk
index=win EventCode=4624 host="{SOURCE_SERVER}" Logon_ID="{LOGON_ID}"
| table _time, host, user, Logon_Type, Source_Network_Address, Logon_ID
| sort _time
```

Use the ID from the **outbound client process on this intermediate host**, rather than reusing the DC's ID.

```text
Compromised workstation → intermediate server → domain controller
                          RDP session A         RDP session B
```

Each hop has its own account, logon/session identifiers, and immediate source IP. The DC normally sees the intermediate server, not the original workstation.

### Assess the Context

An admin workstation connecting to a managed server may be normal. Workstation-to-workstation sessions or unexpected server-originated RDP deserve attention. Approved jump hosts are an important exception. Validate the account role, maintenance window, destinations and executed commands before concluding the activity is malicious.

Source: [TryHackMe — Detecting AD Lateral Movement, Task 6](https://tryhackme.com/room/detectingadlateralmovement). Rewritten notes; correlation caveats are supplementary.
