## ARP Scanning and Subnet-Wide Denial of Service

### 1. Phase 1: The Digital Fingerprint (ARP Scanning)

Before an attacker can launch an "Evil Twin" or "Man-in-the-Middle" attack, they must map the network. They use **ARP Scanning** to see who is "alive."

#### 1.1 The Anatomy of a Scan

In a standard network, ARP requests happen naturally as people connect. In a scan, the behavior changes:

- **Sequential Requests**  
  A single MAC address sends requests for `.1`, then `.2`, then `.3`, and so on, across the entire subnet.

- **Non-Existent Hosts**  
  The attacker asks for IPs that aren't assigned to anyone. On a normal network, you don't ask for someone who isn't there.

- **Tool Signature**  
  This is exactly what tools like **Nmap** or **Netdiscover** do.

---

### 2. Phase 2: The Network Blackout (Subnet-Wide DoS)

Once the scanner identifies all live hosts, the attacker can move from "spying" on one person to crashing the entire office.

#### 2.1 How the Attack Escalates

- **Targeting the Gateway**  
  The attacker tells the router:  
  "Every single IP on this network now belongs to my MAC address."  
  This poisons the router's entire ARP table.

- **Targeting the Clients**  
  The attacker broadcasts to the entire subnet:  
  "I am the Gateway (`192.168.10.1`)."

- **The Result**  
  All traffic from the clients goes to the attacker, and all traffic from the internet goes to the attacker.  
  If the attacker doesn't forward it, the entire subnet goes offline.

---

### 3. Investigation & Hunting Commands

#### 3.1 Detecting the Scan (Reconnaissance)

Use this Wireshark filter to see if someone is "knocking on every door":

```text
arp.opcode == 1 && eth.src == [Source_MAC]
```

Look for **10+ requests in a single second** to sequential IPs.

#### 3.2 Detecting the DoS (The Attack)

To see if the attacker is claiming every IP on the network:

```text
arp.duplicate-address-detected && arp.opcode == 2
```

If you see this warning appearing for multiple different IP addresses but pointing to the **same MAC**, you are witnessing a subnet-wide poison attack.

#### 3.3 CLI Investigation (TShark)

To quickly identify the scanner's MAC from a capture file:

```bash
# This extracts the target IPs being requested by a specific MAC
tshark -r ARP_Scan.pcapng -Y "eth.src == 08:00:27:53:0c:ba" -T fields -e arp.dst.proto_ipv4
```

---

### 4. Response & Remediation (Incident Response)

When you detect these anomalies, your documentation should suggest these "real world" steps:

- **Step 1: Physical Tracing**  
  The attacker’s MAC address is tied to a physical device.  
  Check your switch's MAC address table to find which physical port that device is plugged into.

  ```text
  show mac address-table address [Attacker_MAC]
  ```

- **Step 2: Port Shutdown**  
  Once identified, shut the port to isolate the attacker.

  ```text
  interface [Port_ID]
    shutdown
  ```

- **Step 3: Containment**  
  If the attack is coming over Wi‑Fi (like an Evil Twin), use a deauthentication tool against the attacker's radio to stop their broadcast.


