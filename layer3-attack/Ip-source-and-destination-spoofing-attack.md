## Network Traffic Analysis: IP Spoofing and DoS Attacks

This guide covers common network-layer attacks involving IP source and destination spoofing, focusing on detection patterns and mitigation strategies.

---

### 1. Core Analysis Principles

Apply the **Subnet Trust Rule**:

- **Inbound**: Any packet entering the network with a **source IP from inside the local subnet** is likely a spoofed/crafted packet.
- **Outbound**: Any packet leaving the network with a **source IP not belonging to the local subnet** indicates internal malicious activity or unauthorized packet crafting.

---

### 2. Attack Profiles and Detection

#### 2.1 Decoy Scanning (Nmap `-D`)

Attackers hide their scanning IP among multiple "decoy" addresses to evade IDS/firewall blocking.

- **How it works**  
  The target receives probes from many IPs (decoys) simultaneously. Only one is the real attacker.

- **The reveal**  
  For closed ports, the victim sends a TCP RST packet. The attacker’s machine is the only one that will consistently receive and track these responses to map the network.

- **Detection indicators**
  - Initial fragmentation from fake/unusual addresses.
  - Legitimate TCP traffic mixed with high-volume probes.
  - A single external host receiving an unusually high volume of RST flags from the victim.

---

#### 2.2 Random Source DDoS

A denial-of-service attack where the attacker rapidly changes the source IP of every packet to overwhelm state tables and resources.

- **Reverse Smurf logic**  
  Can appear as many "ghost" hosts pinging a single host, or a victim host sending replies to non-existent IPs.

- **Detection indicators**
  - **Single port utilization**: Massive traffic directed at one specific service port (e.g., 80, 443) from thousands of different IPs.
  - **Incremental base ports**: Attack tools often use a sequential (non-random) source port for each new spoofed IP.
  - **Identical length fields**: Packet payloads are often exactly the same size, unlike organic user traffic.

---

#### 2.3 LAND Attacks (Local Area Network Denial)

A classic DoS where the source and destination addresses are forged to be identical.

- **Mechanism**  
  `Source IP:Port == Destination IP:Port`.

- **Impact**  
  Forces the victim into an infinite loop of responding to itself, leading to CPU exhaustion or system crashes.

- **Detection**  
  Filter for packets where:

  ```text
  ip.src == ip.dst
  ```

---

#### 2.4 SMURF Attacks

An amplification attack using ICMP (Ping) traffic.

- **Flow**
  1. Attacker sends ICMP Echo Request to a **network broadcast address**.
  2. The source IP is spoofed to be the victim's IP.
  3. Every host on that network segment sends an ICMP Echo Reply to the victim.

- **Detection**  
  Look for an **Echo Reply storm**—an excessive amount of ICMP replies hitting a host that never sent the initial requests.

---

#### 2.5 IV Generation (Wireless Attack)

Specific to WEP (Wired Equivalent Privacy) networks.

- **Goal**  
  Capture and re-inject modified packets to force the generation of Initialization Vectors (IVs) for statistical cracking.

- **Detection**  
  High volume of identical/repeated packets between two hosts in a short timeframe.

---

### 3. Traffic Analysis Commands (tcpdump / tshark)

#### 3.1 Extracting Unique Source IPs

To see if you are being hit by a random-source attack:

```bash
# tcpdump: Extract unique IPs from a capture
tcpdump -nn -r analysis.pcap | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -nr
```

#### 3.2 Filtering for ICMP Requests (Smurf / Ping Floods)

```bash
# tshark: List top IPs sending ICMP Echo Requests
tshark -r analysis.pcap -Y "icmp.type == 8" -T fields -e ip.src | sort | uniq -c | sort -nr
```

#### 3.3 Detecting LAND Attacks

```bash
# Filter for packets where source and destination IPs are the same
tcpdump -r analysis.pcap "src host [Victim_IP] and dst host [Victim_IP]"
```

---

### 4. Prevention Strategies

- **Ingress/Egress Filtering**  
  Implement RFC 2827 (BCP 38) to drop packets with spoofed source addresses at the network boundary.

- **uRPF (Unicast Reverse Path Forwarding)**  
  Discard packets if the source IP is not reachable through the interface it arrived on.

- **Stateful inspection**  
  Configure firewalls to reconstruct fragmented packets and validate the 3-way handshake before allowing traffic to internal services.

- **ICMP rate limiting**  
  Restrict the number of ICMP responses a host can generate per second.


