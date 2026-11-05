# Detecting VPN Credential Attacks

A VPN login can authenticate a domain identity. Stolen VPN credentials may therefore provide an internal foothold and credentials usable against other domain resources.

### Authentication Flow

```text
Remote client → VPN gateway → RADIUS / NPS → AD credential validation
                    │              │                 │
             VPN connection log  6272 / 6273      DC authentication log
```

**NPS (Network Policy Server)** is Microsoft's RADIUS server. These NPS events apply when the VPN uses that authentication architecture. Direct LDAP, SAML, or other configurations require the appropriate gateway and identity-provider logs instead.

| NPS event | Meaning | Investigation use |
| --- | --- | --- |
| 6272 | Access granted | Successful network authentication |
| 6273 | Access denied | Inspect user, reason code, and timing |
| 6274 | Request discarded | Investigate request/configuration context |

Reason **16** commonly indicates a bad username or password. A single occurrence can be a typo; repeated failures can indicate a credential attack. Other reason codes can involve policy or configuration. Read the full event description before deciding why access failed.

### Important Splunk Queries

#### 1. Identify denial patterns

```splunk
index=win EventCode=6273
| stats count by User_Account_Name, Client_IP_Address
| sort - count
```

**Warning:** `Client_IP_Address` identifies the **RADIUS client, usually the VPN gateway**, not necessarily the remote attacker's IP. Pivot to gateway logs and, where available, calling-station details to identify the originating client.

#### 2. Look for success after repeated failures

```splunk
index=win EventCode IN (6273,6272) User_Account_Name="{COMPROMISED_USER}"
| table _time, host, EventCode, User_Account_Name, Client_IP_Address
| sort _time
```

Repeated denials followed by a grant are suspicious, but the success could belong to the real user. Correlate session identifiers, source information, and subsequent actions.

#### 3. Correlate Windows logons

```splunk
index=win EventCode IN (4624,4625) user="{COMPROMISED_USER}"
| table _time, host, user, EventCode, Logon_Type, Logon_ID
| sort _time
```

In this room, **NPS runs on the DC**, so the matching logon events appear there. When NPS is separate, inspect that server's authentication events. DC Event **4776** applies to NTLM credential validation; do not assume every VPN authentication uses NTLM.

### What Makes the Activity Suspicious?

| Pattern | Investigation direction |
| --- | --- |
| Many denials for one user | Possible brute force |
| Denials across many users | Possible spraying |
| Grant after a burst of denials | Check whether credentials were compromised |
| One successful login with no failures | Could be valid stolen credentials; investigate context |
| New internal hosts or administrative access | Follow post-authentication activity |

Do not stop at the access-granted event. Establish the assigned VPN address, session time, internal destinations, accessed resources, and whether behavior matches the user's baseline.

Source: [TryHackMe — Detecting AD Initial Access, Tasks 6–7](https://tryhackme.com/room/detectingadinitialaccess). Rewritten notes; architecture and correlation caveats added.
