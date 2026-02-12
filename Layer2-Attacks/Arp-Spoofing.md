## ARP Spoofing (Poisoning) Detection and Response

### 1. Protocol Fundamentals: The "Vanilla" ARP

To detect anomalies, you must understand the baseline. **ARP (Address Resolution Protocol)** maps Layer 3 (IP) addresses to Layer 2 (MAC) addresses.

#### 1.1 The Standard Handshake

- **Request (Opcode 1)**  
  Host A broadcasts:  
  `"Who has IP 192.168.10.4? Tell 192.168.10.5"`

- **Reply (Opcode 2)**  
  Host B unicasts:  
  `"192.168.10.4 is at 50:eb:f6:ec:0e:7f"`

- **Caching**  
  Host A stores this mapping in its ARP cache to avoid constant broadcasting.

---

### 2. The Mechanics of the Attack

ARP Poisoning exploits the **trusting** nature of the protocol. It does not require a request to send a reply (Gratuitous ARP).

- **The Goal**: Redirect traffic through the attacker's machine.
- **The Method**: The attacker sends counterfeit ARP replies to both the victim and the gateway (router):
  - To **Victim**: "I am the Gateway" (Attacker's MAC + Gateway's IP).
  - To **Gateway**: "I am the Victim" (Attacker's MAC + Victim's IP).

#### 2.1 Outcomes

- **DoS**: Attacker drops the traffic.
- **MITM**: Attacker forwards the traffic (often leading to SSL stripping or DNS spoofing).

---

### 3. Hands-On Detection Workflow

#### 3.1 Traffic Capture

If you are on a Linux-based system, use `tcpdump` to capture raw traffic for analysis:

```bash
# Install tcpdump
sudo apt install tcpdump -y

# Capture traffic on eth0 and write to a file
sudo tcpdump -i eth0 -w ARP_Spoof.pcapng
```

#### 3.2 Wireshark Analysis (The Red Flags)

When analyzing `ARP_Spoof.pcapng`, use these specific filters to find the attacker:

| **Analysis Goal**       | **Wireshark Filter**                              |
|-------------------------|---------------------------------------------------|
| Isolate ARP only        | `arp`                                             |
| Find duplicate IPs      | `arp.duplicate-address-detected && arp.opcode == 2` |
| Track specific MAC      | `eth.addr == 08:00:27:53:0c:ba`                   |
| Find original IPs       | `(arp.opcode) && (eth.src == 08:00:27:53:0c:ba)`  |

#### 3.3 Key Indicators of Compromise (IOCs)

- **Address duplication**: Wireshark flags an IP mapped to two different MAC addresses.
- **High frequency**: A single host incessantly broadcasting ARP replies.
- **IP transition**: A MAC address historically linked to one IP (e.g., `.5`) suddenly claiming to be another (e.g., `.4`).

---

### 4. Verification via Command Line

If you suspect an attack is happening live on your Linux machine, check your local cache:

```bash
# Look for the suspicious MAC address in your local table
arp -a | grep 08:00:27:53:0c:ba
```

If you see **two different IPs** associated with that same attacker MAC, you are currently being spoofed.

---

### 5. Mitigation Strategies

- **Static ARP Entries**  
  Manually map critical IPs (like the gateway) to MACs.  
  High maintenance, but un-spoofable.

- **Port Security**  
  Configure switches to allow only one MAC address per physical port.

- **DAI (Dynamic ARP Inspection)**  
  A security feature in high-end switches that validates ARP packets against a trusted database.


