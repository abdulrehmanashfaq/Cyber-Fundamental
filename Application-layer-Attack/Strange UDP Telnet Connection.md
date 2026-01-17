# Network Traffic Analysis: Telnet and UDP Anomalies

This project focuses on the identification of suspicious communication patterns within Telnet and UDP protocols, highlighting how these often-overlooked channels are exploited for command-and-control (C2) and data exfiltration.

---

## Telnet Protocol Analysis

Telnet is a legacy protocol that provides bidirectional, interactive communication. Because it transmits data in plaintext, it is a significant security risk and a primary target for traffic inspection.

### 1. Traditional Traffic Identification (Port 23)
Standard Telnet traffic operates on Port 23. While many modern systems have migrated to SSH, legacy environments or specific terminal services may still utilize it.
* **Security Note:** Since Telnet is unencrypted, payloads are easily inspectable. However, attackers may still encode (e.g., Base64) or obfuscate the text within the Telnet stream to hide their actions.

### 2. Non-Standard Port Utilization (TCP Port Switching)
Attackers often run Telnet services on non-standard ports (such as Port 9999) to bypass basic firewall filters that only look for Port 23.
* **Detection:** Monitoring for high volumes of interactive TCP traffic on unrecognized ports.
* **Analysis Technique:** Using "Follow TCP Stream" in analysis tools to reconstruct the session and identify malicious commands.



### 3. Telnet via IPv6
In networks where IPv6 is enabled but unmonitored, it can be used as a "shadow" communication channel. Identifying Telnet traffic between IPv6 link-local addresses is a key indicator of lateral movement or unauthorized access.
* **Analysis Filter:** `((ipv6.src_host == [Target_Address]) or (ipv6.dst_host == [Target_Address])) and telnet`

---

## UDP Communication Monitoring

UDP (User Datagram Protocol) is often preferred by attackers for exfiltration because it is connectionless, allowing for faster transmission with less protocol overhead than TCP.

### Detecting UDP Anomalies
Unlike TCP, UDP does not require a three-way handshake (SYN, SYN/ACK, ACK). Communication begins immediately.
* **Key Indicator:** Immediate data transmission to an external or unknown IP address without a prior connection setup.
* **Analysis Technique:** Following the UDP stream to inspect the raw data field for encoded payloads or file fragments.



### Comparison of Legitimate UDP Use Cases

| Protocol/Application | Description | Potential Security Risk |
| :--- | :--- | :--- |
| **Real-time Apps** | Media streaming, VoIP, and gaming. | Masking exfiltration as legitimate steady-state streams. |
| **DHCP** | Assigning dynamic IP addresses. | Rogue DHCP servers used for traffic redirection. |
| **SNMP** | Network management and monitoring. | Enumerating network topology and device details. |
| **TFTP** | Simplified file transfer protocol. | Moving malicious payloads onto legacy hardware or IoT devices. |

---

## Investigation Workflow

To effectively analyze these "strange" connections, follow these steps:

1. **Verify the Port:** Determine if the protocol is running on its assigned port or a suspicious alternative.
2. **Examine the Handshake:** For TCP-based Telnet, look for anomalies in the connection phase; for UDP, look for sudden spikes in data volume.
3. **Follow the Stream:** Reconstruct the communication to determine if the payload contains human-readable commands, script execution, or encoded data.
4. **Check Address Families:** Ensure both IPv4 and IPv6 traffic are being monitored for hidden tunnels.
