## HTTP/HTTPS Enumeration: Recognizing Web Fuzzing in Traffic

This note covers how directory/file fuzzing against web servers looks in logs and PCAPs, and how to respond.

---

### 1. Behavioural Signs of Fuzzing

Automation stands out when you know what to look for:

- **Request rate way beyond human speed**  
  One client IP hammering hundreds or thousands of URLs per minute.

- **Huge spike in 404/403 responses**  
  Brute‑force discovery of hidden paths means most guesses fail, so your error counters jump sharply.

- **Odd URL patterns**  
  Long wordlists, predictable prefixes, or paths that clearly come from common dictionaries (e.g., `/backup.zip`, `/old/`, `/test/`).

Together, these are strong hints of tools like `ffuf`, Gobuster, or custom scripts.

---

### 2. Reading the Web Server Logs

On busy sites, it’s often quicker to hunt in access logs than to open a PCAP.

- **Simple grep for a suspect IP**

  ```bash
  grep "192.168.10.5" access.log
  ```

- **Using awk to focus on the source field**

  ```bash
  awk '$1 == "192.168.10.5"' access.log
  ```

Things to check:

- Distribution of status codes (e.g., very high 404/403 ratio).  
- Repeated probing of similar paths with minor variations.  
- Whether User‑Agent strings look like tools instead of browsers.

---

### 3. Zooming In with Wireshark

If you have a capture (e.g., `web_enum.pcapng`), useful display filters include:

| Filter           | Use case                                                         |
|------------------|------------------------------------------------------------------|
| `http`           | All HTTP traffic                                                |
| `http.request`   | Only client requests                                            |
| `ip.src == X.X.X.X` | Only what the suspected scanner sends                        |

Once filtered:

- Use **Follow → HTTP Stream** on a single request/response pair to see the full conversation.  
- Look for systematic walking of directories or file extensions.

---

### 4. Smarter Enumeration and Evasion Tricks

More careful attackers may:

- **Throttle their speed** – One request every few seconds to stay under simple rate limits.  
- **Spread across many IPs** – Using proxies/bots so no single address looks noisy.  
- **Fuzz parameters instead of paths** – Playing with query strings or JSON fields to trigger logic bugs (e.g., flipping `role=user` → `role=admin`).

These behaviours are less obvious but still show up as:

- Unusual parameter values.  
- Rare endpoints being hit by multiple different clients.  
- Repeated failures followed by a single successful response.

---

### 5. Hardening the Web Tier

- **Tune error handling**  
  Avoid leaking too much detail in 4xx/5xx messages. Some setups deliberately normalize errors, but be careful not to break normal troubleshooting.

- **Deploy and tune a WAF**  
  Block or challenge IPs that generate sustained streams of 404/403 or match known scanner signatures.

- **Lock down sensitive paths**  
  Ensure `.git/`, backups, `.env`, admin panels, and debug endpoints are either removed, moved, or properly access‑controlled.


