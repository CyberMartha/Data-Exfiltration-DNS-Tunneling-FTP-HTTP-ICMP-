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
| **Splunk (SIEM)** | Log ingestion (`dns_logs`), SPL statistical aggregation, and query-length anomaly filtering | [splunk.com](https://splunk.com) |
| **Wireshark** | Packet capture analysis, conversation statistics, TCP stream reconstruction, and payload inspection | [wireshark.org](https://wireshark.org) |
| **MITRE ATT&CK** | Adversary behavior classification (`TA0010` — Exfiltration Over Alternative Protocol) | [attack.mitre.org](https://mitre.org) |
| **TryHackMe** | *SOC Level 1 — Network Security Monitoring: Data Exfiltration Detection* lab environment | [tryhackme.com](https://tryhackme.com/room/dataexfildetection) |

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

<img width="1309" height="674" alt="image" src="https://github.com/user-attachments/assets/afa755cc-7f36-4f89-92a4-f30456d0e730" />
<img width="1302" height="669" alt="image" src="https://github.com/user-attachments/assets/37af5a64-e851-41ba-8ca5-d2cf8d41780e" />




---

### 2. Detection: Cleartext Data Exfiltration via FTP (`MITRE T1048.003`)
Because File Transfer Protocol (FTP) transmits both authentication commands (`USER`, `PASS`) and file payloads (`STOR`, `RETR`) in cleartext over TCP ports 21 and 20, deep packet inspection reveals full session context and transferred file contents.

* **Wireshark Analysis:**
  * Filtered control and data channels using `ftp || ftp-data` and `ftp.request.command`.
  * Used **Follow -> TCP Stream** on active sessions to audit authentication events and reconstruct transferred file payloads.
* **Key Findings:**
  * Observed **5 unauthorized FTP connections** initiated using the **`guest`** account.
  * Audited privileged **`root`** account FTP activity and reconstructed the `ftp-data` stream to identify the exfiltrated customer-related file and embedded verification artifact.

<!-- SCREENSHOT 3: Wireshark Follow TCP Stream showing FTP login sessions and exfiltrated file payload -->
<img width="1366" height="600" alt="Wireshark FTP Control and Data Stream Reconstruction" src="PASTE_WIRESHARK_FTP_SCREENSHOT_URL_HERE" />

---

### 3. Detection: Application-Layer Exfiltration via HTTP (`MITRE T1048.002`)
Adversaries frequently disguise data theft as routine web traffic by embedding sensitive files or encoded strings inside outbound HTTP `POST` request bodies.

* **Wireshark & Splunk Analysis:**
  * Filtered outbound web traffic using `http.request.method == "POST"` (and checked high `bytes_out` transfers in Splunk).
  * Inspected HTTP headers, URI paths, and form/body payloads using **Follow -> HTTP Stream**.
* **Key Findings:**
  * Confirmed compromised internal host **`192.168.1.103`** was actively transmitting sensitive data over cleartext HTTP.
  * Extracted and inspected the HTTP request body to uncover the hidden exfiltrated data payload.

<!-- SCREENSHOT 4: Wireshark or Splunk view of outbound HTTP POST exfiltration from 192.168.1.103 -->
<img width="1366" height="600" alt="HTTP POST Data Exfiltration Payload Inspection" src="PASTE_HTTP_EXFIL_SCREENSHOT_URL_HERE" />

---

### 4. Detection: Covert Exfiltration via ICMP Tunneling (`MITRE T1048.003`)
Standard `ping` utilities generate ICMP Echo Request packets (`type 8`) with small, predictable OS padding. Attackers abuse the ICMP data field to smuggle arbitrary file chunks out of networks where outbound ICMP is left unrestricted.

* **Wireshark Analysis:**
  * Isolated outbound echo requests with abnormal payload sizes using `icmp.type == 8 && data.len > 64` (or `icmp && frame.len > 74`).
  * Examined the **Data** layer in the packet bytes pane across sequential ICMP requests to extract ASCII/Hex strings hidden inside the ping payloads.
* **Key Findings:**
  * Detected anomalous, oversized ICMP Echo Request packets carrying custom data strings rather than standard diagnostic padding.
  * Reconstructed the sequential ICMP payload chunks to confirm covert data exfiltration.

<!-- SCREENSHOT 5: Wireshark showing oversized ICMP Echo Request packets and custom payload bytes -->
<img width="1366" height="600" alt="Wireshark ICMP Tunneling Oversized Echo Request Payload" src="PASTE_ICMP_EXFIL_SCREENSHOT_URL_HERE" />

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
