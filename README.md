# live-traffic-cyber-threat-analysis-using-honeypot-and-elk-stack
This project demonstrates my ability to design and deploy a live cyber threat monitoring environment using production-grade tools and methodologies. I engineered a system that leverages honeypots to attract and log malicious activity, and integrated the ELK Stack (Elasticsearch, Logstash, Kibana) for real-time analysis and visualisation of threat data.

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

---

## Deployment Steps

> **For a detailed setup guide, see [`/deployment`](./deployment)**

1. Provision infrastructure (locally/EC2).
2. Deploy TPOT and configure honeypots.
3. Set up ELK Stack and custom Logstash pipelines.
4. Harden network with firewall rules.
5. Start monitoring and analyzing collected data.

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
  - [Insert dashboard screenshots here]

---

End-to-end honeypot deployment capturing global threat activity and visualizing insights with Suricata and ELK Stack. Ideal for SOC and threat hunting.
