# Network Security Monitoring Case Study: Multi-Vector Data Exfiltration Detection

## Objective
The primary objective of this investigation was to detect, correlate, and reconstruct unauthorized network-based data exfiltration across multiple protocols within a simulated enterprise environment. By combining **Splunk (SIEM)** log ingestion and Search Processing Language (SPL) queries with deep packet inspection in **Wireshark**, this project demonstrates Tier-1/Tier-2 Security Operations Center (SOC) alert triage and threat hunting across **DNS, FTP, HTTP, and ICMP** exfiltration channels.

---

## Skills Learned & Core Competencies
* **SIEM Log Ingestion & SPL Threat Hunting (Splunk):** Indexing structured network logs (`index="data_exfil"`) and writing statistical SPL queries (`stats`, `where len()`, `sort`) to isolate anomalous outbound traffic spikes and high-entropy domains.
* **Covert Channel & Tunneling Detection:** Identifying data smuggled inside everyday network protocols, including oversized DNS subdomain queries and non-standard ICMP Echo Request payloads.
* **Deep Packet Inspection (Wireshark):** Applying precision display filters (`dns`, `ftp`, `ftp-data`, `http`, `icmp`), evaluating endpoint conversation statistics, and reconstructing TCP/HTTP streams.
* **Cross-Tool Correlation:** Pivoting between Splunk log aggregations and raw packet captures (`pcapng`) to attribute exfiltration activity to compromised internal endpoints (`192.168.1.103`).
* **MITRE ATT&CK Mapping:** Aligning observed adversary behaviors with **TA0010 (Exfiltration)** techniques to support structured incident documentation and perimeter remediation.

---

## Tools & Frameworks Used

| Tool / Framework | Role in Investigation | Reference |
| :--- | :--- | :--- |
|     <img src="https://img.shields.io/badge/-Splunk-000000?&style=for-the-badge&logo=Splunk&logoColor=white" /> | Log ingestion (`dns_logs`), SPL statistical aggregation, and query-length anomaly filtering | [splunk.com](https://splunk.com) |
|  <img src="https://img.shields.io/badge/-Wireshark-1679A7?&style=for-the-badge&logo=Wireshark&logoColor=white" /> | Packet capture analysis, conversation statistics, TCP stream reconstruction, and payload inspection | [wireshark.org](https://wireshark.org) |
| **MITRE ATT&CK** | Adversary behavior classification (`TA0010` — Exfiltration Over Alternative Protocol) | [attack.mitre.org](https://mitre.org) |
| <img src="https://img.shields.io/badge/-TryHackMe-222831?&style=for-the-badge&logo=TryHackMe&logoColor=white" /> | *SOC Level 1 — Network Security Monitoring: Data Exfiltration Detection* lab environment | [tryhackme.com](https://tryhackme.com/room/dataexfildetection) |

---

## Executive Summary

Adversaries routinely bypass traditional firewall rules by abusing trusted, permitted network protocols to smuggle sensitive files out of compromised internal hosts. In this investigation, I analyzed network telemetry and packet captures exhibiting four distinct network-based exfiltration techniques: **DNS Tunneling, FTP File Transfers, HTTP POST Exfiltration, and ICMP Tunneling**.

Through systematic log analysis in Splunk and packet reconstruction in Wireshark, I isolated the compromised internal host (**`192.168.1.103`**), identified the external Command-and-Control (C2) domain (**`tunnelcorp.net`**), uncovered unauthorized privileged/guest FTP sessions, and extracted hidden exfiltrated payloads across HTTP and ICMP streams.

---

## Investigation Walkthrough & Technical Analysis

### 1. Detection: Data Exfiltration via DNS Tunneling (`MITRE T1048.003`)
Attackers encode stolen data into long, high-entropy subdomain labels and transmit them as standard DNS queries to an authoritative name server under their control, bypassing perimeter controls that allow outbound UDP/53 traffic.

* **Splunk SPL Analysis:**
  * Ingested the DNS telemetry dataset and ran statistical aggregations to identify anomalous destination domains:
    ```spl
    index="data_exfil" sourcetype="dns_logs" | stats count by query | sort -count
    ```
  * Isolated abnormally long subdomain payloads using character-length thresholds:
    ```spl
    index="data_exfil" sourcetype="dns_logs" | where len(query) > 30
    ```
* **Wireshark Verification:** Applied `dns.flags.response == 0` alongside frame/query length filters (`dns and frame.len > 70`) and reviewed **Statistics -> Conversations / Endpoints** to pinpoint the top talker.
* **Key Findings:**
  * Identified **`tunnelcorp.net`** as the rogue external domain receiving encoded DNS queries.
  * Isolated **315 suspicious DNS tunneling events/packets**.
  * Attributed the highest volume of suspicious outbound DNS requests to compromised internal host **`192.168.1.103`**.

<!-- SCREENSHOT 1: Splunk SPL query showing index="data_exfil" and the 315 tunnelcorp.net events -->

<img width="1311" height="671" alt="image" src="https://github.com/user-attachments/assets/29a9a416-3da7-4556-a16a-d1b5ebec3052" />
<img width="1306" height="619" alt="image" src="https://github.com/user-attachments/assets/ea69ba65-a708-469e-9928-5ee4dfac51da" />
<img width="1308" height="665" alt="image" src="https://github.com/user-attachments/assets/d4d9c525-5a3e-4630-9bd7-3c4fdfa9dbc6" />

<img width="1309" height="674" alt="image" src="https://github.com/user-attachments/assets/afa755cc-7f36-4f89-92a4-f30456d0e730" />
<img width="1302" height="669" alt="image" src="https://github.com/user-attachments/assets/37af5a64-e851-41ba-8ca5-d2cf8d41780e" />




---

### 2. Detection: Cleartext Data Exfiltration via FTP (`MITRE T1048.003`)
Attackers frequently abuse File Transfer Protocol (FTP) to move large datasets out of a network using compromised credentials, misconfigured servers, or ephemeral accounts. Because FTP transmits both control commands and file payloads in cleartext over TCP ports 21 and 20, deep packet inspection of `ftp-lab.pcap` provides full visibility into authentication events, upload commands, and transferred files.

#### Investigation Methodology & Wireshark Filters
* **Step 1 — Isolate FTP Control & Data Channels:** Applied `ftp || ftp-data` to filter out background noise and isolate active FTP control sessions alongside ephemeral `PASV` data transfers.
* **Step 2 — Audit Cleartext Authentication (`USER` / `PASS`):** Filtered login attempts using `ftp.request.command == "USER" || ftp.request.command == "PASS"` to identify suspicious usernames, weak passwords, and unauthorized account logins.
* **Step 3 — Hunt for File Upload Commands & Sensitive Extensions:** Isolated outbound file transfers using `ftp contains "STOR"` and targeted high-value file extensions using `ftp contains "csv"`.
* **Step 4 — Inspect Large Frame Payloads:** Applied `ftp && frame.len > 90` to isolate oversized packets carrying substantial command arguments or embedded document payloads.
* **Step 5 — Reconstruct Sessions via TCP Streams:** Used **Right-Click -> Follow -> TCP Stream** on flagged control and `ftp-data` packets to reassemble full session transcripts and inspect the exact contents of transferred files.

#### Key Findings
* **Unauthorized Account Activity:** Identified **5 unauthorized FTP connections** authenticated via the **`guest`** account alongside privileged activity from the **`root`** account.
* **Sensitive File Exfiltration:** Confirmed an external IP connected via the `guest` account and exfiltrated sensitive `.csv` files (`STOR` commands), while oversized frames (`frame.len > 90`) revealed additional sensitive documents being staged and transferred out of the network.


<!-- SCREENSHOT 3: Wireshark Follow TCP Stream showing FTP login sessions and exfiltrated file payload -->
<img width="1302" height="668" alt="image" src="https://github.com/user-attachments/assets/d14423b5-4424-44f2-9755-29c02f648e69" />
<img width="1313" height="672" alt="image" src="https://github.com/user-attachments/assets/06c1327f-d074-4861-882c-8fa49832011c" />
<img width="1302" height="669" alt="image" src="https://github.com/user-attachments/assets/484b1310-7d38-4580-9d45-2ca6578eb391" />
<img width="1309" height="678" alt="image" src="https://github.com/user-attachments/assets/b3139c44-b3c1-4dd0-b175-2c02251d7957" />
<img width="1308" height="666" alt="image" src="https://github.com/user-attachments/assets/cd2de491-9cf0-4be9-bf81-29fd4f6bccaa" />
<img width="1310" height="673" alt="image" src="https://github.com/user-attachments/assets/b9770d47-7396-4043-92e6-466475177b70" />




---

### 3. Detection: Application-Layer Exfiltration via HTTP (`MITRE T1048.002`)
Adversaries routinely abuse HTTP to exfiltrate data because web traffic blends into standard enterprise activity and easily traverses perimeter firewalls. Using obfuscation techniques such as Base64 encoding, custom headers, or chunked `POST` uploads, attackers smuggle files out to external hosts. To detect this activity, I correlated high-level web proxy telemetry in **Splunk** (`http_logs`) with deep packet inspection in **Wireshark** (`http_lab.pcap`).

#### Phase 1: SIEM Log Baselining & Anomaly Hunting (Splunk)
* **Step 1 — Baseline HTTP Telemetry:** Queried all indexed web traffic (`index="data_exfil" sourcetype="http_logs"`) across *All Time* to establish baseline request volume.
* **Step 2 — Isolate Outbound `POST` Uploads:** Narrowed results to upload-capable requests using `index="data_exfil" sourcetype="http_logs" method=POST`.
* **Step 3 — Profile Outbound Byte Volume by Domain:** Calculated request frequency alongside average, minimum, and maximum payload sizes per destination domain to spot statistical outliers:
  ```spl
  index="data_exfil" sourcetype="http_logs" method=POST 
  | stats count avg(bytes_sent) max(bytes_sent) min(bytes_sent) by domain 
  | sort - count
  ```
* **Step 4 — Filter High-Byte Exfiltration Events:** Isolate large outbound uploads exceeding 600 bytes to pinpoint the exact source IP, destination domain/IP, URI, and timestamp:
  ```spl
  index="data_exfil" sourcetype="http_logs" method=POST bytes_sent > 600 
  | table _time src_ip uri domain dst_ip bytes_sent 
  | sort - bytes_sent
  ```

#### Phase 2: Packet-Level Correlation & Stream Reconstruction (Wireshark)
* **Step 1 — Filter HTTP & `POST` Methods:** Opened `http_lab.pcap` and applied `http`, then narrowed to `http.request.method == "POST"` to separate outbound uploads from routine `GET` browsing.
* **Step 2 — Progressive Frame-Length Reduction:** Filtered out small form submissions with `http.request.method == "POST" and frame.len > 500`, then tightened the threshold to `http.request.method == "POST" and frame.len > 750` to eliminate remaining noise and isolate the exact exfiltration frame seen in Splunk.
* **Step 3 — Reconstruct HTTP Stream:** Used **Right-Click -> Follow -> HTTP Stream** on the isolated packet to inspect the raw request headers and extract the exfiltrated document payload.

#### Key Findings
* **Cross-Source Attribution:** Correlated the Splunk `bytes_sent > 600` outlier directly with the single `frame.len > 750` packet in `http_lab.pcap`, confirming compromised internal host **`192.168.1.103`** uploaded data to an external server.
* **Payload Recovery:** Reconstructing the HTTP stream exposed the secret document contents transmitted in the `POST` body.


<img width="1305" height="620" alt="image" src="https://github.com/user-attachments/assets/ccf011d6-d8a9-4b9f-93d4-59b259af0332" />
<img width="1301" height="658" alt="image" src="https://github.com/user-attachments/assets/8938fa7e-2cc2-4516-9c9f-2c6e014defad" />
<img width="1310" height="628" alt="image" src="https://github.com/user-attachments/assets/f9b794ea-15b0-4390-95f9-fda688084cc0" />
<img width="1310" height="597" alt="image" src="https://github.com/user-attachments/assets/9eda329d-0cf1-4f92-8485-8ac187ad4dac" />
<img width="1312" height="650" alt="image" src="https://github.com/user-attachments/assets/1c5e7e3c-741b-43d1-8c00-c34b27c34979" />
<img width="1287" height="632" alt="image" src="https://github.com/user-attachments/assets/a6fead0c-6ad7-4e1c-9e63-0b61934a89e6" />

---

### 4. Detection: Covert Exfiltration via ICMP Tunneling (`MITRE T1048.003`)
Internet Control Message Protocol (ICMP) is designed for network diagnostics and error reporting (such as `ping` Echo Requests and Replies). Because firewalls often permit outbound ICMP and inspect it less strictly than TCP or UDP, adversaries abuse the ICMP data field to smuggle encoded file chunks (Base64/Hex) out to a remote listener. To detect this covert channel, I analyzed `icmp_lab.pcap` in **Wireshark**.

#### Investigation Methodology & Wireshark Filters
* **Step 1 — Isolate All ICMP Traffic:** Applied `icmp` to separate diagnostic and control packets from background network activity and establish baseline ICMP volume.
* **Step 2 — Filter Outbound Echo Requests:** Narrowed the capture to outbound `ping` requests using `icmp.type == 8` to focus specifically on host-initiated traffic leaving the internal network.
* **Step 3 — Isolate Oversized Packet Payloads:** Applied `icmp.type == 8 and frame.len > 100` to filter out standard diagnostic pings (which typically measure **~74 bytes** total) and flag packets carrying unusually large, non-standard payloads.
* **Step 4 — Inspect Payload Bytes:** Examined the **Internet Control Message Protocol -> Data** section in the Packet Details and Packet Bytes panes across sequential requests to verify non-default ASCII/Hex strings.

#### Key Findings
* **Anomalous Frame Sizes:** Separated legitimate ~74-byte `ping` traffic from oversized `icmp.type == 8` packets exceeding **100 bytes**, confirming data smuggling inside the ICMP payload section.
* **Covert Channel Verification:** Inspected the packet bytes pane of flagged Echo Requests to confirm the presence of structured, non-standard exfiltrated data rather than routine OS diagnostic padding.

<img width="1304" height="665" alt="image" src="https://github.com/user-attachments/assets/f208bf49-5bd4-4a1b-8042-dacbfdb405cc" />
<img width="1309" height="661" alt="image" src="https://github.com/user-attachments/assets/311fba62-7b9e-4655-9bc3-a4433530191d" />
<img width="1308" height="667" alt="image" src="https://github.com/user-attachments/assets/00ff6df5-4f8d-477f-9744-33b84cf120af" />


---

## Summary of Indicators of Compromise (IoCs) & Detections

| Exfiltration Channel | Tool(s) Used | Filter / SPL Query | Confirmed Lab Findings | MITRE ATT&CK |
| :--- | :--- | :--- | :--- | :--- |
| **DNS Tunneling** | Splunk & Wireshark | `index="data_exfil" sourcetype="dns_logs"` / `dns.flags.response == 0` | **315 suspicious queries** to `tunnelcorp.net`; top talker **`192.168.1.103`** | `T1048.003` |
| **FTP Transfer** | Wireshark | `ftp \|\| ftp-data` (Follow TCP Stream) | **5 connections** from `guest`; sensitive customer file exfiltrated via `root` | `T1048.003` |
| **HTTP Exfiltration** | Wireshark & Splunk | `http.request.method == "POST"` (Follow HTTP Stream) | Compromised host **`192.168.1.103`** exfiltrating encoded data via HTTP | `T1048.002` |
| **ICMP Tunneling** | Wireshark | `icmp.type == 8 && data.len > 64` | Oversized ICMP Echo Requests smuggling non-standard payload chunks | `T1048.003` |

---

## Defensive Recommendations & SOC Remediation
1. **DNS Egress Filtering & Length Alerting:** Restrict outbound `UDP/53` exclusively to internal DNS resolvers and deploy SIEM correlation rules alerting on high query volumes or domain lengths exceeding 50 characters.
2. **Block Legacy Cleartext Protocols:** Disable and block outbound FTP (`TCP/20-21`) and unencrypted HTTP (`TCP/80`) at the perimeter firewall; enforce SFTP and HTTPS with TLS inspection.
3. **ICMP Payload & Rate Limiting:** Block outbound ICMP Echo Requests at the perimeter or enforce strict packet size limits (`<= 64 bytes` payload) to prevent ICMP tunneling.
