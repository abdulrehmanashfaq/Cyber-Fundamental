# Password-Based Attacks

Entra ID's internet-facing authentication endpoints can be targeted with guessed, stolen, or reused credentials. An attacker does not need an internal network foothold to attempt a sign-in.

### Password Spraying vs Brute Force

| Pattern | Password spraying | Brute force |
| --- | --- | --- |
| Target | Many accounts | One or a few accounts |
| Guesses | Small set of likely passwords | Many candidate passwords |
| Log shape | Failures spread across usernames | Failures concentrated on a username |
| Evasion | Spread accounts, sources or time | Throttle guesses and vary sources |

**Credential stuffing** is related: attackers test username/password pairs exposed elsewhere. Logs may suggest it, but generally do not reveal the submitted password itself.

Lockout thresholds discourage repeated guessing, but are not a complete detector. Slow attempts can span long windows; distributed attempts can make each IP appear quiet. A correct stolen password may produce one success with no earlier failure.

### Important Splunk Queries

The room's password practice dataset is **`index="task-2"`** with `sourcetype="azure:aad:signin"`.

#### 1. Inspect failures — course filter

```splunk
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| table _time, userPrincipalName, appDisplayName, ipAddress, location.countryOrRegion, status.errorCode, status.failureReason
| sort 0 _time
```

**Interpretation caveat:** this is the room's filter, not a universal definition of failure. `conditionalAccessStatus` describes policy evaluation, not the overall authentication outcome. Excluding CA successes can hide relevant records; missing fields can also be excluded. Begin with all relevant records and inspect error codes and authentication steps when validating a production hunt.

#### 2. Scope accounts targeted by each IP

```splunk
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0 conditionalAccessStatus!=success
| stats dc(userPrincipalName) as targeted_accounts count as failures by ipAddress
| sort - failures
```

Many distinct users suggest spraying. A single user with repeated failures suggests brute force, but confirm chronology and other sources before attributing the attempts.

#### 3. Successes for a targeted user

```splunk
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0 userPrincipalName="{TARGET_USER}"
| stats count by userPrincipalName, status.errorCode, ipAddress
```

#### 4. Successes from a suspicious IP

```splunk
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"=0 ipAddress="{SUSPICIOUS_IP}"
| stats count by userPrincipalName, status.errorCode
```

#### 5. Time-bucketed scoping — supplementary template

```splunk
index="task-2" sourcetype="azure:aad:signin" "status.errorCode"!=0
| bin _time span=15m
| stats count as failures dc(userPrincipalName) as targeted_accounts values(userPrincipalName) as users by _time, ipAddress
| sort 0 _time
```

No fixed alert threshold is implied. Inspect wider windows for throttled activity and compare with expected services and user behavior.

### Investigation Method

1. Identify failure sources, target count and timing.
2. Compare short bursts with slower repeated attempts.
3. Search for successful access by both identity and source.
4. Check MFA, policy result, client, device and location.
5. Follow audit and M365 activity after the suspected compromise.

Source: [TryHackMe — Entra ID Monitoring, Task 2](https://tryhackme.com/room/entraidmonitoring). Rewritten notes, with the additional time-bucket query marked as a study template.
