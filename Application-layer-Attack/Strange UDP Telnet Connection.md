## Telnet Over Odd Ports and Suspicious UDP Traffic

This note covers how Telnet and UDP can be abused as quiet channels for C2 and exfiltration, and what to look for in PCAPs.

---

## 1. Telnet: Old Protocol, New Problems

Telnet is a clear‑text, interactive protocol. Anything typed goes over the wire readable by anyone on the path.

### 1.1 Classic Telnet on Port 23

Where it still exists, you’ll usually see:

- TCP port 23 as the destination.  
- Clear‑text usernames, passwords, and shell commands when you follow the stream.

Even though the content is visible, attackers may still:

- Encode payloads (e.g., Base64 blobs) to hide intent from quick visual inspection.  
- Use Telnet as a simple remote shell in legacy networks.

### 1.2 Telnet on Non‑Standard Ports

To dodge simple port‑based filters, attackers can run Telnet daemons on ports like 9999 instead of 23.

Detection ideas:

- Look for **interactive‑looking TCP flows** (lots of small packets back and forth) on unexpected ports.  
- Use “Follow TCP Stream” in Wireshark to reconstruct the conversation and see whether it looks like a shell.

### 1.3 Telnet over IPv6

In environments where IPv6 is enabled but not monitored, it becomes a side channel.

Useful filter example:

```text
((ipv6.src == [Target_Address]) or (ipv6.dst == [Target_Address])) and telnet
```

This helps surface sessions that never show up in IPv4‑only dashboards.

---

## 2. UDP as a Lightweight Exfil Channel

UDP doesn’t have a handshake; senders can start pushing data immediately.

### 2.1 What to Watch For

- Traffic that **immediately carries payloads** to an external IP with no preceding connection setup.  
- Steady, periodic UDP packets that all have similar sizes, especially to rare or unknown destinations.

In Wireshark, “Follow UDP Stream” can show whether the payloads look like:

- Encoded text.  
- File fragments.  
- Simple command/response patterns.

### 2.2 Legitimate vs. Suspicious Uses

| Use case          | Normal behaviour                          | Possible abuse                                    |
|-------------------|--------------------------------------------|--------------------------------------------------|
| Streaming/VoIP    | Continuous, predictable flows             | Hiding exfil in background media flows           |
| DHCP              | Bursts on local segments                  | Rogue DHCP servers steering traffic elsewhere    |
| SNMP              | Sporadic management polling               | Mapping network topology for later attacks       |
| TFTP              | Simple file transfers                     | Dropping payloads onto legacy/IoT devices        |

---

## 3. Basic Investigation Flow

When you see “weird” Telnet/UDP traffic:

1. **Check ports** – Is it using the expected port or something unusual?  
2. **Review the handshake pattern** – For TCP, confirm SYN/SYN‑ACK/ACK looks normal; for UDP, note immediate data.  
3. **Follow the stream** – Rebuild the Telnet or UDP conversation and actually read the payload.  
4. **Compare IPv4 vs. IPv6** – Make sure you don’t miss tunnels that only exist on one address family.

