## HTTP/HTTPS Service Enumeration

### 1. Detection via Traffic Patterns

The most obvious sign of fuzzing is a sudden spike in volume. Automated tools like **ffuf**, **DirBuster**, or **Gobuster** send requests much faster than a human could ever click.

- **Excessive volume**: A single IP address making hundreds or thousands of requests per minute.
- **The "404 spike"**: In directory fuzzing, the goal is to find hidden files. Since most guesses will be wrong, your logs will show a massive amount of `404 Not Found` or `403 Forbidden` errors in a very short window.

---

### 2. Analyzing Logs (The "Paper Trail")

You can use Linux command-line tools to parse Apache/Nginx access logs. This is often faster than opening a massive PCAP file in Wireshark.

- **Grep vs. Awk for investigation**
  - **grep**: Quickly find every line associated with a suspicious IP.

    ```bash
    cat access.log | grep "192.168.10.5"
    ```

  - **awk**: More precise filtering (e.g., only looking at the first column where the IP is stored).

    ```bash
    cat access.log | awk '$1 == "192.168.10.5"'
    ```

---

### 3. Wireshark Investigation Techniques

If you are analyzing a capture file like `<filename>.pcapng`, use specific filters to cut through the noise of background network traffic:

| **Filter**          | **Purpose**                                                         |
|---------------------|---------------------------------------------------------------------|
| `http`             | Shows all HTTP traffic (requests and responses).                   |
| `http.request`     | Shows only what the attacker is asking for (HTTP requests only).   |
| `ip.src == <IP>`   | Isolates traffic coming from the suspected attacker.               |

- **Follow HTTP Stream**: Right‑click a packet and choose "Follow HTTP Stream" to see the full conversation in a readable format.

---

### 4. Advanced Fuzzing & Evasion

Sophisticated attackers often avoid obvious spikes and may:

- **Stagger (rate limit) requests**: Send one request every few seconds or minutes to stay under automated rate‑limiting thresholds.
- **Use distributed fuzzing**: Leverage multiple IP addresses (proxies or botnets) so that no single host looks suspicious.
- **Perform parameter/JSON fuzzing**: Instead of only looking for files, they look for logic errors. For example, changing `return=max` to `return=min` to manipulate the data the server sends back.

---

### 5. Defensive Strategies

To stop or hinder these attempts, you should:

- **Configure response codes carefully**: Some servers can be configured to return a generic error or even a `200 OK` for everything to confuse scanners (although this can break normal functionality).
- **Use WAF rules**: Configure a Web Application Firewall to automatically block IPs that trigger too many `404` or `403` responses in a short period.
- **Harden virtual hosts**: Ensure your server does not expose sensitive files like `.git`, `.bash_history`, or `.env` if they are accidentally left in the web root.


