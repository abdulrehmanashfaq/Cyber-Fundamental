## Analysing Odd DNS Traffic: Enumeration and Tunnels

This note is about spotting when DNS is being abused—either for heavy recon or as a covert data channel.

---

## 1. Quick DNS Refresher

DNS is the Internet’s addressing service: it turns names into IPs.

Typical resolution path:

1. Client asks for `firstpage.example.com`.  
2. OS cache is checked; if no hit, the query goes to a **recursive resolver**.  
3. The resolver queries **root servers** to find which TLD server (`.com`, `.org`, etc.) is responsible.  
4. The TLD server points it to the **authoritative nameserver** for `example.com`.  
5. The authoritative server returns an `A`/`AAAA` record.  
6. The resolver caches the result and returns it to the client.

### 1.1 Common Query Styles

| Query type      | What it does                                                  |
|-----------------|---------------------------------------------------------------|
| Recursive       | Resolver must return the final answer or an error.           |
| Iterative       | Resolver can respond with “go ask this other server.”        |
| Reverse (PTR)   | Asks “who owns this IP?” via `in-addr.arpa` / `ip6.arpa`.    |

---

## 2. DNS Enumeration in Captures

Enumeration is just DNS being used as a recon tool to map infrastructure.

In something like `dns_enum_detection.pcapng`, look for:

- **ANY queries** – Type `ANY` (255) asking for all available data about a name.  
- **Spikes in NXDOMAIN** – Brute‑force subdomain lists cause lots of “name does not exist” replies.  
- **AXFR attempts** – Zone transfer requests over TCP/53 trying to pull the full zone.

All of these are much rarer in normal user traffic, but very common in tools.

---

## 3. DNS as a Tunneling Channel

### 3.1 How Tunnels Use DNS

Attackers can tunnel data inside DNS by:

- Splitting data into small chunks.  
- Encoding chunks (often Base64).  
- Embedding them in either:
  - **TXT records**, or  
  - Long, weird‑looking subdomains (e.g., `<encoded_blob>.exfil.attacker.com`).

The recursive resolver and intermediate firewalls usually just see this as “someone making lots of DNS queries.”

### 3.2 Indicators in `dns_tunneling.pcapng`

- TXT answers with long, non‑human text.  
- Sequences of subdomains that look random but share a common base domain.  
- Multiple layers of encoding (data that still looks like Base64 after one decode).

On the analysis side, you’d export those strings and try decoding step by step to reconstruct the original payload.

---

## 4. Handy Record-Type Cheat Sheet

| Record | Normal use                                  | Abuse pattern                                     |
|--------|---------------------------------------------|---------------------------------------------------|
| A/AAAA | Name → IP                                   | Target discovery, host fingerprinting             |
| PTR    | IP → name (reverse lookup)                 | Reverse sweeps to find hidden assets              |
| TXT    | Arbitrary text                             | Exfil and C2 payloads                             |
| MX     | Mail routing                               | Targeting mail infra and phishing infrastructure  |
| CNAME  | Aliases                                     | Hiding C2 domains behind “legit” names            |
| SOA    | Zone metadata                              | Gathering admin info and timing details           |

---

## 5. IPFS Side Note

Attackers increasingly host payloads on content‑addressed systems like IPFS.  
From a network perspective, you might see:

- Requests to public gateways such as:  
  `https://cloudflare-ipfs.com/ipfs/<HASH>`

It’s worth adding those gateways to your monitoring lists, as a surprising number of malware campaigns lean on them to store second‑stage code.

