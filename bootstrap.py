import os
import subprocess
import sys
import shutil

def ensure_dependency(command, install_hint):
    if shutil.which(command) is None:
        print(f"[!] {command} is not installed.")
        print(f"    Hint: {install_hint}")
        return False
    return True

def install_pip_packages():
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyshark", "requests"])
        print("[✓] Python packages installed successfully.")
    except subprocess.CalledProcessError:
        print("[!] Failed to install Python packages. Please run: pip install pyshark requests")

folders = {
    "analyzer": ["__init__.py", "extract.py", "enrich.py", "mitre_mapper.py"],
    "reports": ["__init__.py", "reporter.py"]
}

starter_content = {
    "analyzer/extract.py": '''import pyshark

def extract_iocs(pcap_path):
    cap = pyshark.FileCapture(pcap_path, display_filter="http || dns")
    iocs = {"ips": set(), "domains": set(), "uris": set(), "user_agents": set()}

    for pkt in cap:
        try:
            if "IP" in pkt:
                iocs["ips"].add(pkt.ip.dst)
            if "DNS" in pkt:
                iocs["domains"].add(pkt.dns.qry_name)
            if "HTTP" in pkt:
                iocs["uris"].add(pkt.http.request_full_uri)
                iocs["user_agents"].add(pkt.http.user_agent)
        except AttributeError:
            continue

    cap.close()
    return {k: list(v) for k, v in iocs.items()}
''',

    "analyzer/enrich.py": '''import requests

USE_VT = False
USE_ABUSEIPDB = False
USE_OTX = False
API_KEYS = {}

def set_services(vt=False, abuse=False, otx=False, keys={}):
    global USE_VT, USE_ABUSEIPDB, USE_OTX, API_KEYS
    USE_VT = vt
    USE_ABUSEIPDB = abuse
    USE_OTX = otx
    API_KEYS = keys

def query_virustotal(value):
    headers = {"x-apikey": API_KEYS['vt']}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{value}" if value.count('.') == 3 else f"https://www.virustotal.com/api/v3/domains/{value}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json = response.json()
        score = json['data']['attributes']['last_analysis_stats']['malicious']
        return f"malicious score: {score}"
    return "no data"

def query_abuseipdb(ip):
    headers = {"Key": API_KEYS['abuseipdb'], "Accept": "application/json"}
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json = response.json()
        score = json['data']['abuseConfidenceScore']
        return f"abuse score: {score}"
    return "no data"

def query_otx(value):
    headers = {"X-OTX-API-KEY": API_KEYS['otx']}
    type_ = "domain" if not value.count('.') == 3 else "IPv4"
    url = f"https://otx.alienvault.com/api/v1/indicators/{type_}/{value}/general"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        json = response.json()
        pulses = len(json.get('pulse_info', {}).get('pulses', []))
        return f"in {pulses} threat pulses"
    return "no data"

def enrich_iocs(iocs):
    enriched = {}
    for key in iocs:
        enriched[key] = []
        for item in iocs[key]:
            result = {"value": item, "score": "unknown", "source": "local"}
            if USE_VT:
                result["score"] = query_virustotal(item)
                result["source"] = "VirusTotal"
            elif USE_ABUSEIPDB and key == "ips":
                result["score"] = query_abuseipdb(item)
                result["source"] = "AbuseIPDB"
            elif USE_OTX:
                result["score"] = query_otx(item)
                result["source"] = "AlienVault OTX"
            enriched[key].append(result)
    return enriched
''',

    "analyzer/mitre_mapper.py": '''def map_to_mitre(iocs):
    mappings = []
    for uri in iocs.get("uris", []):
        uri_val = uri["value"] if isinstance(uri, dict) else uri
        if "login" in uri_val or "auth" in uri_val:
            mappings.append({"technique": "T1078", "name": "Valid Accounts"})

    for domain in iocs.get("domains", []):
        domain_val = domain["value"] if isinstance(domain, dict) else domain
        if domain_val.endswith(".top") or domain_val.endswith(".xyz"):
            mappings.append({"technique": "T1566.002", "name": "Spearphishing Link"})

    return mappings
''',

    "reports/reporter.py": '''def generate_report(iocs, mitre_techniques, output_path):
    with open(output_path, "w") as f:
        f.write("# PCAP Threat Hunter Report\n\n")
        f.write("## Indicators of Compromise\n")
        for k, v in iocs.items():
            f.write(f"### {k}\n")
            for item in v:
                if isinstance(item, dict):
                    f.write(f"- {item['value']} ({item['score']}) from {item['source']}\n")
                else:
                    f.write(f"- {item}\n")

        f.write("\n## MITRE ATT&CK Techniques\n")
        for m in mitre_techniques:
            f.write(f"- {m['technique']}: {m['name']}\n")
'''
}

def create_structure():
    for folder, files in folders.items():
        os.makedirs(folder, exist_ok=True)
        for filename in files:
            full_path = os.path.join(folder, filename)
            if not os.path.exists(full_path):
                with open(full_path, "w") as f:
                    f.write(starter_content.get(full_path, ""))
    print("[✓] Project directories and files initialized.")

if __name__ == "__main__":
    print("[*] Initializing PCAP Threat Hunter project...")

    tshark_ok = ensure_dependency("tshark", "Install via: https://www.wireshark.org/download.html or your OS package manager.")
    if not tshark_ok:
        print("[!] TShark is required by pyshark. Please install it before running the tool.")

    install_pip_packages()
    create_structure()
    print("[✓] Bootstrap complete.")
