import argparse
import os
from analyzer.extract import extract_iocs
from analyzer.enrich import enrich_iocs, set_services
from analyzer.mitre_mapper import map_to_mitre
from reports.reporter import generate_report

# Ensure required directories and files exist
os.makedirs("analyzer", exist_ok=True)
os.makedirs("reports", exist_ok=True)
open("analyzer/__init__.py", "a").close()
open("reports/__init__.py", "a").close()

# Entry point for the CLI tool
def main():
    parser = argparse.ArgumentParser(description="PCAP Threat Hunter - Analyze PCAPs, Extract IOCs, Map to MITRE")
    parser.add_argument("pcap", help="Path to the PCAP file")
    parser.add_argument("--output", default="reports/report.md", help="Path to the output report file")
    parser.add_argument("--enrich", action="store_true", help="Enable threat intelligence enrichment")
    args = parser.parse_args()

    if args.enrich:
        print("[+] Choose enrichment services (Y/N):")
        use_vt = input("Use VirusTotal? (Y/N): ").strip().lower() == 'y'
        use_abuseipdb = input("Use AbuseIPDB? (Y/N): ").strip().lower() == 'y'
        use_otx = input("Use AlienVault OTX? (Y/N): ").strip().lower() == 'y'

        keys = {}
        if use_vt:
            keys['vt'] = input("Enter your VirusTotal API key: ").strip()
        if use_abuseipdb:
            keys['abuseipdb'] = input("Enter your AbuseIPDB API key: ").strip()
        if use_otx:
            keys['otx'] = input("Enter your OTX API key: ").strip()

        set_services(use_vt, use_abuseipdb, use_otx, keys)

    print("[+] Extracting IOCs from PCAP...")
    iocs = extract_iocs(args.pcap)

    if args.enrich:
        print("[+] Enriching IOCs with threat intelligence...")
        iocs = enrich_iocs(iocs)

    print("[+] Mapping to MITRE ATT&CK techniques...")
    mitre_techniques = map_to_mitre(iocs)

    print("[+] Generating report...")
    generate_report(iocs, mitre_techniques, args.output)
    print(f"[✓] Report saved to {args.output}")

if __name__ == "__main__":
    main()
