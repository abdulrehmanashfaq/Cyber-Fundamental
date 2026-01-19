# Deep Dive: Elastic Stack (ELKB) Architecture

## 1. Introduction
The Elastic Stack (formerly ELK Stack) is a collection of open-source software tools—**Elasticsearch**, **Logstash**, **Kibana**, and **Beats**—that provide a complete pipeline for searching, analyzing, and visualizing data in real-time. In the context of Cybersecurity, this stack serves as the foundation for a **SIEM (Security Information and Event Management)** solution.



## 2. Core Components

### A. Elasticsearch (The Search & Storage Engine)
Elasticsearch is a distributed, RESTful search and analytics engine built on Apache Lucene. It acts as the central database for the stack.
* **Data Structure:** It is JSON-based and schema-free (though schemas like ECS are best practice).
* **Indexing:** Instead of tables, data is stored in "Indices."
* **Performance:** It uses inverted indices to allow for near real-time search capabilities across petabytes of data.
* **Interaction:** All operations (indexing, searching, administration) are performed via **REST APIs** (GET, POST, PUT, DELETE).

### B. Logstash (The Processing Pipeline)
Logstash is a server-side data processing pipeline that ingests data from multiple sources simultaneously, transforms it, and sends it to a "stash" (usually Elasticsearch). It follows a strict "Event Processing Pipeline":
1.  **Input:** Ingests raw data. Common inputs include:
    * `file`: Reading from static log files.
    * `syslog`: Listening on port 514 for system logs.
    * `beats`: Receiving data from Beats agents.
2.  **Filter (Transform):** The critical phase for normalization.
    * **Grok:** Parses unstructured text into structured fields.
    * **Mutate:** Renames, strips, or modifies fields to match the **Elastic Common Schema (ECS)**.
    * **GeoIP:** Adds geographical metadata to IP addresses.
3.  **Output:** Ships the processed data to Elasticsearch, console, or file.

### C. Kibana (The Visualization Interface)
Kibana is the window into the Elastic Stack. It sits on top of Elasticsearch and provides the user interface.
* **Discover:** Interactive exploration of raw data.
* **Visualize:** Creation of charts, maps, and graphs.
* **Dashboards:** Aggregating visualizations for SOC monitoring.
* **SIEM App:** A dedicated security application within Kibana for threat hunting.

### D. Beats (The Data Shippers)
Beats are lightweight, single-purpose data shippers installed on edge hosts (endpoints). They solve the "resource-intensive" problem of running Logstash on every server.
* **Filebeat:** For forwarding log files.
* **Winlogbeat:** For shipping Windows Event Logs.
* **Packetbeat:** For analyzing network traffic (acting like a distributed Wireshark).

## 3. Advanced Architecture: Buffering & Resiliency
In enterprise environments with high data volume (Quantitative metrics), a simple pipeline is insufficient. We introduce "Buffers" to prevent data loss.

* **Message Queuing (Kafka / RabbitMQ / Redis):** Placed between Beats and Logstash. If Elasticsearch slows down, data queues here instead of being dropped.
* **Security (Nginx):** Placed in front of Kibana to provide Reverse Proxy services, SSL/TLS encryption, and authentication.

---
