# live-traffic-cyber-threat-analysis-using-honeypot-and-elk-stack
This project demonstrates my ability to design and deploy a live cyber threat monitoring environment using production-grade tools and methodologies. I engineered a system that leverages honeypots to attract and log malicious activity, and integrated the ELK Stack (Elasticsearch, Logstash, Kibana) for real-time analysis and visualisation of threat data.

**Table of Contents**
- [Architecture Overview](#architecture-overview)
- [Tools & Technologies Used](#tools--technologies-used)
- [Deployment Steps](#deployment-steps)
- [Threat Data Analysis Highlights](#threat-data-analysis-highlights)
- [Attack Trends & Notable Insights](#attack-trends--notable-insights)
- [Contributions & AI Integration](#contributions--ai-integration)

Key capabilities showcased include:

**Threat Intelligence Collection:** Deployed and hardened honeypots (Cowrie/Dionaea) to emulate vulnerable services, capturing SSH brute-force attempts, malware delivery, and scanning behaviours from live internet traffic.

**Log Aggregation & SIEM Functionality:** Built a custom ELK pipeline to centralise, enrich, and visualise attack data, simulating the core functions of a Security Information and Event Management (SIEM) platform.

**Security Automation:** Wrote custom parsing rules and enrichment scripts in Python and Logstash to classify threats, extract indicators of compromise (IoCs), and generate time-based visual analytics.

**Network & Cloud Security Foundations:** Configured firewall rules, segmented the honeynet, and optionally deployed infrastructure on AWS for scalability and remote monitoring.

This project reflects my ability to apply offensive deception techniques and defensive monitoring tools to gain actionable insight into real-world threat behaviour—skills that are directly applicable in SOC, cyber threat intelligence, and defensive security engineering roles.

---

## Architecture Overview

A simple network diagram illustrates the flow between TPOT (honeypot orchestration), the ELK stack, and the data pipeline. (Insert diagram here)

**Data Flow:**  
1. Internet-sourced attacks hit TPOT-managed honeypots (Cowrie/Dionaea).  
2. Events are logged and shipped via Logstash to Elasticsearch.  
3. Kibana visualizes live threat data for analysis.

---

## Tools & Technologies Used

- **TPOT**: Honeypot orchestration
- **Cowrie, Dionaea**: Emulated services for attack capture
- **Elasticsearch, Logstash, Kibana (ELK Stack)**: Centralized log management and visualization
- **Python**: Parsing/enrichment scripts
- **FirewallD/UFW**: Network segmentation and control
- **AWS EC2, VirtualBox**: Cloud/on-premise deployment
- **AI/ML (Optional Enhancement)**: Integration of anomaly detection models for automated threat pattern recognition and alerting

---

## Deployment Steps

> **For a detailed setup guide, see [`/deployment`](./deployment)**

1. **Provision an AWS EC2 instance**  
   - Instance type: `t2.large`  
   - Storage: **50GB**  
   - OS: Ubuntu 20.04 or later recommended  
2. **Configure firewall to allow all inbound traffic**  
   - Simulate real-world attacks from multiple sources by allowing all traffic (0.0.0.0/0) in the AWS Security Group attached to the instance.
3. **Prepare the system**  
   - Update and upgrade the OS:
     ```bash
     sudo apt update && sudo apt upgrade -y
     ```
4. **Install TPOT CE (Community Edition)**
   - Clone the TPOT setup repository:
     ```bash
     git clone https://github.com/telekom-security/tpotce
     cd tpotce
     sudo ./install.sh
     ```
5. **Choose and configure the "Hive" deployment mode**
   - During installation, select the "Hive" (multi-honeypot + ELK) profile.
   - When prompted, set your desired username and password for the dashboard.
6. **Access the TPOT Dashboard**
   - After successful installation and reboot, access the management dashboard via your instance's public IP at:
     ```
     https://<your_instance_public_ip>:<TPOT_dashboard_port>
     https://github.com/fakowajo123/live-traffic-cyber-threat-analysis-using-honeypot-and-elk-stack/blob/main/screenshots/kibana%20Dashboard.jpg
     ```
   - (The default TPOT dashboard port is usually `64297`, but confirm in the output after install.)

---

## Threat Data Analysis Highlights

- **Key attacks captured:**  
  - SSH brute-force attempts  
  - Malware upload attempts  
  - Automated scans

- **Notable Indicators of Compromise (IoCs):**  
  - Attacker IPs  
  - Malicious payload hashes  
  - Suspicious command patterns

- **Kibana Dashboards:**  
  ![Kibana Dashboard ](https://github.com/fakowajo123/live-traffic-cyber-threat-analysis-using-honeypot-and-elk-stack/blob/main/screenshots/Kibana%20Dashboard..jpg)

---

## Attack Trends & Notable Insights

- **Notable CVEs Exploited:**  
  - [List significant CVEs observed in attack payloads, e.g., CVE-2002-0013 (EternalBlue), CVE-2001-0414 (Log4Shell), CVE-2020-11900 (Log4Shell etc.]

- **Most Frequent Attack Countries:**  
  - [Top attacking source countries, e.g., China, Russia, USA, etc. — Based on geo-IP analysis]

- **Most Targeted Ports:**  
  - [List common ports attacked: 5005(Java Debug Wire Protocol), 445 (SMB), 30001 (Kubernetes NodePort Services), etc.]

- **Alert Categories:**  
  - [Examples: Attempted Administrative Acesss, Misc Attack, Recon/Scanning(Attempted INformation Leak), Exploit Attempt, etc.]

---

## Contributions & AI Integration

- **AI-Powered Threat Detection:**  
  - Integrated AI-driven anomaly detection to automatically identify unusual traffic patterns and advanced persistent threats (APTs) within the honeypot data.  
  - Machine learning models can be trained on collected data to classify incoming threats and predict potential attack vectors, contributing to smarter defense strategies.

- **Automated Response for Defense:**  
  - The system can be extended to respond defensively to detected threats, such as dynamic firewall adjustments, automatic blacklisting of hostile IPs, or triggering alerts for SOC investigation—making the environment proactive, not just reactive.

---

End-to-end honeypot deployment capturing global threat activity and visualizing insights with Suricata and ELK Stack. Ideal for SOC and threat hunting.
