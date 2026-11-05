# Detecting OWA Credential Attacks

**Exchange** provides the email service, **Outlook** is a client, and **OWA** is its browser interface. Internet-facing OWA lets attackers attempt domain credentials without first reaching an internal workstation.

### What the Login Looks Like

A login commonly sends a POST to `/owa/auth.owa`. Both successful and failed logins can return **HTTP 302**. A failure may redirect to the login page with `reason=2`; success redirects towards the mailbox.

**A 302 response is not proof of success.** Inspect the redirect context and Windows authentication logs. The IIS `cs_username` field may be empty for forms-based OWA authentication.

| Path | Meaning | Why it matters |
| --- | --- | --- |
| `/owa/` | Browser mail interface | Login attempts and mailbox access |
| `/owa/auth.owa` | Login processing endpoint | Authentication request bursts |
| `/ecp/` | Exchange administrative interface | Follow-up administrative activity |
| `/powershell/` | Exchange remote management endpoint | Potential remote administration |

Access to an administrative path is a lead; it does not by itself prove the account had permission or performed a change.

### Important Splunk Queries

#### 1. Find bursts of login requests

```splunk
index=iis cs_uri_stem="/owa/auth.owa" cs_method=POST
| bin _time span=5m
| stats count by _time, c_ip
| where count > 10
| sort - count
```

This is the room's example threshold, not a production rule. Distributed or slow attacks can avoid it. The query counts requests, not confirmed authentication failures.

#### 2. Identify targeted users

```splunk
index=win EventCode=4625
| stats count by user, Logon_Type
| sort - count
```

| Pattern in authentication logs | Possible explanation |
| --- | --- |
| Many failures against one account | Brute force |
| Failures spread across many accounts | Password spraying |
| Failures followed by success | Possible compromise requiring correlation |

#### 3. Build the user's authentication timeline

```splunk
index=win EventCode IN (4624,4625) user="{TARGETED_USER}" Logon_Type=8
| table _time, host, EventCode, user, Process_Name, Logon_Type
| sort _time
```

The room shows **Type 8 (NetworkCleartext)** for OWA authentication. This describes the logon mechanism, not proof that the password travelled over the internet without TLS. Other deployment configurations can produce different logon types.

The events are on the web server handling authentication. Their source address may be missing or local, so use IIS to recover the HTTP client address and correlate by server and time. Shared NAT/proxy addresses and concurrent logins make this association less certain.

#### 4. Follow activity after authentication

```splunk
index=iis c_ip="{ATTACKER_IP}"
| stats count by cs_uri_stem
| sort - count
```

Then inspect timestamped requests to `/ecp` and `/powershell`, endpoint processes, and Exchange audit records to establish what actually happened.

Source: [TryHackMe — Detecting AD Initial Access, Tasks 4–5](https://tryhackme.com/room/detectingadinitialaccess). Rewritten notes with supplementary interpretation caveats.
