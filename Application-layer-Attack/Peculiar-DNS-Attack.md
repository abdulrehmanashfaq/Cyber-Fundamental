#  Peculiar DNS Traffic Analysis

This project documents the analysis of malicious DNS traffic patterns, focusing on identifying enumeration attempts and data exfiltration through tunneling.

---

##  How DNS Works: The Resolution Process

DNS acts as the **"Phonebook of the Internet."** It translates human-readable domain names into machine-readable IP addresses through a hierarchical process.



### The 8-Step Resolution Cycle:
1. **Query Initiation:** User requests a domain (e.g., `firstpage.example.com`).
2. **Local Cache Check:** The client checks its own OS cache.
3. **Recursive Query:** If not found, the request goes to the Recursive Resolver.
4. **Root Servers:** The resolver asks a Root Server (one of 13 worldwide) where to find the TLD.
5. **TLD Servers:** The Root directs the resolver to the `.com` or `.org` nameservers.
6. **Authoritative Servers:** The TLD server points to the specific nameservers for `example.com`.
7. **Final Resolution:** The resolver queries the domain's authoritative server for the `A` record.
8. **Response:** The resolver returns the IP to the client and caches it.

---

##  Types of DNS Queries

| Query Type | Description |
| :--- | :--- |
| **Recursive** | The client demands the final answer; the server does all the "legwork." |
| **Iterative** | The server provides its best answer or a referral to another server. |
| **Reverse (PTR)** | Maps an IP back to a hostname (e.g., `6.10.168.192.in-addr.arpa`). |



---

##  1. DNS Enumeration Detection
DNS enumeration is the reconnaissance phase where an attacker maps the network's infrastructure.

### Indicators found in `dns_enum_detection.pcapng`:
* **ANY Queries:** DNS type `ANY` (255) used to pull all available records.
* **Subdomain Bruteforcing:** Massive spikes in `NXDOMAIN` (Name Error) responses.
* **AXFR (Zone Transfer):** Attempts to download the entire DNS database via TCP Port 53.

---

##  2. DNS Tunneling and Exfiltration
Tunneling exploits DNS to move data across network boundaries, often bypassing firewalls.

### Indicators found in `dns_tunneling.pcapng`:
* **TXT Record Abuse:** Large strings of arbitrary data stored in the Text field.
* **Encoded Subdomains:** Data is "chunked" and encoded in the subdomain prefix.
* **Multi-Layer Encoding:** Attackers frequently double or triple encode data in Base64.

### Decoding Exfiltrated Data
To retrieve the true value from a triple-encoded string, use the following command in Linux:

---

##  Summary of DNS Record Types

| Record Type | Official Purpose | Malicious Use Case |
| :--- | :--- | :--- |
| **A / AAAA** | Maps a domain name to an IPv4/IPv6 address. | Identifying the IP addresses of live targets. |
| **PTR** | Maps an IP address back to a hostname (Reverse DNS). | **Reverse Network Sweeping** to discover hidden hosts. |
| **TXT** | Stores arbitrary text information. | **Data Exfiltration** and Command & Control (C2). |
| **MX** | Identifies the mail servers for a domain. | Targeting an organization's email infrastructure. |
| **CNAME** | Creates an alias for a domain name. | Hiding C2 traffic behind legitimate-looking aliases. |
| **SOA** | Administrative info about the DNS zone. | Gathering admin emails and zone details. |

---

##  The Interplanetary File System (IPFS)
Recent observations show actors using IPFS to host malicious payloads. Always monitor traffic to known gateways:
* `https://cloudflare-ipfs.com/ipfs/[HASH]`
---

##  Summary of DNS Record Types

| Record Type | Official Purpose | Malicious Use Case |
| :--- | :--- | :--- |
| **A / AAAA** | Maps a domain name to an IPv4/IPv6 address. | Identifying the IP addresses of live targets. |
| **PTR** | Maps an IP address back to a hostname (Reverse DNS). | **Reverse Network Sweeping** to discover hidden hosts. |
| **TXT** | Stores arbitrary text information. | **Data Exfiltration** and Command & Control (C2). |
| **MX** | Identifies the mail servers for a domain. | Targeting an organization's email infrastructure. |
| **CNAME** | Creates an alias for a domain name. | Hiding C2 traffic behind legitimate-looking aliases. |
| **SOA** | Administrative info about the DNS zone. | Gathering admin emails and zone details. |

---

##  The Interplanetary File System (IPFS)
Recent observations show actors using IPFS to host malicious payloads. Always monitor traffic to known gateways:
* `https://cloudflare-ipfs.com/ipfs/[HASH]`
