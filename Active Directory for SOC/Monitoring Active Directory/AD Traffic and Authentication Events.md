# AD Traffic and Authentication Events

AD monitoring starts with **who authenticated, to what, from where, when, and with what result**. Directory activity creates records on different machines. DC logs provide authentication and directory context; endpoint logs show the session and actions on the target.

### Main Protocols

| Protocol | Common ports | Purpose |
| --- | --- | --- |
| Kerberos | TCP/UDP 88 | Ticket-based authentication |
| LDAP / LDAPS | 389 / 636 | Directory queries and modifications |
| Global Catalog | 3268 / 3269 | Forest-wide directory searches |
| SMB | 445; legacy sessions may use 139 | File shares and remote administration |
| RDP | 3389 | Remote interactive access |
| NetBIOS / LLMNR | 137–138 / 5355 | Legacy name resolution and related traffic |

Ports are investigation context, not proof of a particular attack. DNS and other infrastructure protocols also matter.

### Domain Users vs Local Users

| Identity | Credential database | Where to investigate |
| --- | --- | --- |
| Domain user | AD database `NTDS.dit` on DCs | DC validation/ticket events **and target-host logons** |
| Local user | Local SAM | Local machine's authentication/logon records |

**Important:** DC logs do not contain every action or target-side logon. Cached domain logons and ticket reuse also mean not every session produces a new DC authentication event.

### Kerberos Flow

```text
Client → DC/KDC: TGT request             4768 on DC
Client → DC/KDC: service ticket request  4769 on DC
Client → target: use ticket / session   4624 on target where applicable
```

Event **4771** records Kerberos pre-authentication failure. Inspect its failure code; a typo, a stale service password, and malicious guessing need different responses.

| Ticket encryption value | Algorithm | Interpretation |
| --- | --- | --- |
| `0x11` | AES-128 | Can be normal |
| `0x12` | AES-256 | Common modern encryption |
| `0x17` | RC4-HMAC | Investigate against compatibility baseline |

RC4 is a useful hunting signal, but not proof of Kerberoasting. AES tickets can also be roasted.

#### TGT activity

```splunk
index=win EventCode=4768
| table _time, host, Account_Name, Client_Address, Ticket_Encryption_Type
| sort _time
```

#### Unique accounts requesting TGTs

```splunk
index=win EventCode=4768
| stats dc(Account_Name) as unique_accounts
```

### NTLM Flow

```text
Client → target → credential validator
                    4776 on validator
          target records the resulting logon (4624/4625)
```

For domain accounts, the validator is commonly a DC. For a local account, it is the machine holding that account. Inspect the event's result/status to distinguish success from failure.

```splunk
index=win EventCode=4776
| table _time, host, Logon_Account, Source_Workstation
| sort _time
```

```splunk
index=win EventCode=4624 Authentication_Package=NTLM
| table _time, host, user, Workstation_Name, Source_Network_Address, Authentication_Package
| sort _time
```

NTLM can be associated with legacy applications or access by IP address. Unexpected new NTLM use deserves investigation, but volume alone does not establish an attack.

Source: [TryHackMe — Monitoring Active Directory, Tasks 2–3](https://tryhackme.com/room/monitoringactivedirectory). Rewritten notes with supplementary accuracy caveats.
