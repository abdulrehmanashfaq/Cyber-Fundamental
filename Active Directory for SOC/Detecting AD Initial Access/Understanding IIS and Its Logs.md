# Understanding IIS and Its Logs

An internet-facing application can become an entry point into Active Directory when it uses domain identities. Compromising the application or one of its users may give the attacker credentials and access that extend beyond the web server.

**IIS (Internet Information Services)** is Microsoft's web server. It hosts applications such as on-premises Exchange, SharePoint, and internal portals. For investigation, combine the HTTP request with authentication and endpoint events.

```text
External request → IIS / application → AD authentication
                      │                     │
                 HTTP access log       DC authentication logs
                 Security logons
                 Sysmon processes/files
```

### IIS Log Basics

The room uses `C:\inetpub\logs\LogFiles\W3SVC1` as the log directory. The site number can differ on other servers. W3C logs have a `#Fields` header describing the columns.

| IIS field | Meaning | Investigation use |
| --- | --- | --- |
| `c-ip` | HTTP client's IP | Identify the request source; account for proxies |
| `cs-uri-stem` | Requested path | Find login endpoints or unusual scripts |
| `cs-uri-query` | URL query string | Look for commands and failure indicators |
| `cs-method` | HTTP method | Separate GET requests from POST activity |
| `sc-status` | Response status | Spot scanning, failures, and successful responses |
| `cs(User-Agent)` | Client identifier | Recognize automation, while remembering it can be spoofed |

**Important:** W3C timestamps are UTC. Normalize timestamps before correlating sources. Windows Event Viewer may display local time, while event XML records UTC; Splunk display time also depends on its settings.

### Normal vs Suspicious

| Pattern | Usually normal | Investigate |
| --- | --- | --- |
| Volume | A few logins and occasional errors | Large bursts of requests or failures |
| Path | Expected application endpoints | An unfamiliar `.aspx` under a static-content directory |
| Query | Application parameters | `cmd=whoami` or another OS command |
| Method | POST to a login form | Repeated POSTs to an unexpected script |
| Status | Occasional 404 | Hundreds of 404s from one source |

### Authentication Events

| Event | Where to look | Meaning |
| --- | --- | --- |
| 4624 | Server accepting the logon | Successful logon |
| 4625 | Server processing the attempt | Failed logon |
| 4776 | Credential validator, commonly a DC for domain accounts | NTLM credential validation |

The authentication protocol matters: **4776 is for NTLM**, not every AD authentication. Kerberos uses its own ticket events. IIS and Windows events complement each other; neither alone tells the whole story.

Source: [TryHackMe — Detecting AD Initial Access, Task 2](https://tryhackme.com/room/detectingadinitialaccess). Rewritten study notes; timestamp and authentication caveats added for accuracy.
