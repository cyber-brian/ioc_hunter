# PCAP IOC Hunter
A modular, Python-based network forensics tool that extracts IOCs from PCAPs, enriches them with threat intel (VirusTotal, AbuseIPDB, OTX), and maps activity to MITRE ATT&amp;CK. Designed for SOC analysts, threat hunters, and cybersecurity engineers.

# PCAP Threat Hunter

This is a work-in-progress project. It's designed for analysts and engineers who want fast, clean insight from packet data without needing to spin up an entire SIEM or cluster of tools.

PCAP Threat Hunter pulls indicators from traffic, enriches them with optional threat intel (VirusTotal, AbuseIPDB, OTX), and maps them to MITRE ATT&CK techniques all in a single CLI pass. Modular by design and easy to extend.

---

## Features

- IOC extraction (IP addresses, domains, URIs, user agents)
- Optional enrichment via VT, AbuseIPDB, and AlienVault OTX
- MITRE ATT&CK mapping (simple heuristics for now)
- Markdown reporting for easy review or sharing
- CLI-based, no fluff

---

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/pcap-threat-hunter.git
cd pcap-threat-hunter
python bootstrap.py         # Creates all needed files + installs deps
python hunter.py file.pcap  # Run analysis (use --enrich to add threat intel)
