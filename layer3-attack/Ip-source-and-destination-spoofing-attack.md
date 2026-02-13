## IP Spoofing and DoS: Reading the Story in the Packets

This note walks through common IP spoofing patterns and how they show up in packet captures, with a focus on denial‑of‑service and noisy recon.

---

### 1. Baseline Idea: Who Should Own Which IP?

A simple mental model that works well in practice:

- **Inbound traffic**  
  Packets coming **from the internet** should never claim to have a **source IP from your internal subnet**. When they do, someone is forging addresses.

- **Outbound traffic**  
  Packets leaving your network should use **only your own address space**. If you see random external ranges as the source, a host is crafting traffic.

Keeping that “trust boundary” in mind makes spoofing stand out more clearly.

---

### 2. Common Spoofing Patterns

#### 2.1 Decoy Scans (e.g., Nmap `-D`)

Here the attacker hides among a crowd of fake IPs:

- The target receives probes from many different apparent sources.
- Only one of those IPs is actually under attacker control and sees the responses.

**How you notice it**:

- RST responses (for closed ports) all flow back **toward one real host** out on the internet.
- The probe side has weird fragmentation or uncommon address ranges.
- Legitimate traffic is mixed with bursts of short‑lived probes.

#### 2.2 Random‑Source DDoS

For DoS, the goal is to exhaust state and bandwidth, not stay invisible.

- Each packet has a **different fake source IP**.
- The victim replies (if UDP/ICMP) to thousands of non‑existent hosts.

Look for:

- A single destination IP and port (e.g., TCP/80, UDP/53) being hammered by traffic from a huge variety of sources.
- Source ports that walk up sequentially while IPs jump around.
- Packets that are identical in size and structure, suggesting a generator tool.

#### 2.3 LAND Attacks

A throwback technique that still appears in some captures:

- `ip.src` and `ip.dst` are **exactly the same**, including the port.
- The target device ends up sending traffic to itself repeatedly.

Wireshark / tcpdump detection is straightforward:

```text
ip.src == ip.dst
```

#### 2.4 Smurf‑Style ICMP Amplification

Classic ICMP spoofing:

1. Attacker sends ICMP Echo Requests **to a broadcast address**.
2. They forge the **source IP** to be the victim.
3. Every host on that LAN replies to the victim with Echo Replies.

In a capture, this looks like an **Echo Reply storm** toward a single victim that never actually sent the initial requests.

#### 2.5 WEP IV Generation (Wireless)

On legacy WEP networks, attackers may:

- Capture and then replay or slightly modify traffic.
- Force access points to generate lots of new Initialization Vectors (IVs) for cracking.

You’ll see unnaturally repetitive frames between the same MACs in a short window.

---

### 3. CLI Patterns for Large Captures

When PCAPs are too big for manual clicking, `tcpdump` and `tshark` are your friends.

#### 3.1 Who Is Hitting Me? (Unique Sources)

```bash
# Summarize source IP frequency from a capture
tcpdump -nn -r analysis.pcap \
  | awk '{print $3}' \
  | cut -d. -f1-4 \
  | sort | uniq -c | sort -nr
```

Great for spotting random‑source floods.

#### 3.2 ICMP Request Hotspots (Smurf / Ping Flood)

```bash
# Top IPs sending ICMP Echo Requests
tshark -r analysis.pcap -Y "icmp.type == 8" \
  -T fields -e ip.src | sort | uniq -c | sort -nr
```

#### 3.3 LAND Candidates

```bash
# Packets where source and destination are identical
tcpdump -nn -r analysis.pcap "src host [Victim_IP] and dst host [Victim_IP]"
```

---

### 4. Hardening Against Spoofing

- **Ingress/egress filtering (BCP 38)**  
  Drop traffic with source addresses that don’t logically belong on that interface.

- **uRPF (Unicast Reverse Path Forwarding)**  
  Discard packets if the routing table says the source IP should never arrive from that direction.

- **Stateful firewalls**  
  Make middleboxes validate the full three‑way handshake before allowing access to sensitive services.

- **Rate‑limit ICMP and other reflection vectors**  
  Slow down amplification channels so they are less attractive to attackers and easier to spot.

