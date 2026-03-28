"""MITRE ATT&CK mapping for network-observable techniques."""
from models import MitreRef
from typing import List

BASE_URL = "https://attack.mitre.org/techniques"

_DB = {
    # Reconnaissance
    "port_scan": [
        MitreRef(tactic="reconnaissance", technique_id="T1046",
                 technique_name="Network Service Discovery",
                 url=f"{BASE_URL}/T1046"),
    ],
    "host_discovery": [
        MitreRef(tactic="reconnaissance", technique_id="T1018",
                 technique_name="Remote System Discovery",
                 url=f"{BASE_URL}/T1018"),
    ],
    # Initial Access / Delivery
    "web_attack": [
        MitreRef(tactic="initial-access", technique_id="T1190",
                 technique_name="Exploit Public-Facing Application",
                 url=f"{BASE_URL}/T1190"),
    ],
    # Credential Access
    "cleartext_creds_http": [
        MitreRef(tactic="credential-access", technique_id="T1552",
                 technique_name="Unsecured Credentials",
                 subtechnique_id="T1552.001",
                 subtechnique_name="Credentials In Files",
                 url=f"{BASE_URL}/T1552/001"),
    ],
    "cleartext_creds_ftp": [
        MitreRef(tactic="credential-access", technique_id="T1552",
                 technique_name="Unsecured Credentials",
                 url=f"{BASE_URL}/T1552"),
    ],
    "kerberoasting": [
        MitreRef(tactic="credential-access", technique_id="T1558",
                 technique_name="Steal or Forge Kerberos Tickets",
                 subtechnique_id="T1558.003",
                 subtechnique_name="Kerberoasting",
                 url=f"{BASE_URL}/T1558/003"),
    ],
    # Defense Evasion
    "dns_tunneling": [
        MitreRef(tactic="command-and-control", technique_id="T1071",
                 technique_name="Application Layer Protocol",
                 subtechnique_id="T1071.004",
                 subtechnique_name="DNS",
                 url=f"{BASE_URL}/T1071/004"),
        MitreRef(tactic="exfiltration", technique_id="T1048",
                 technique_name="Exfiltration Over Alternative Protocol",
                 url=f"{BASE_URL}/T1048"),
    ],
    # Command & Control
    "c2_beaconing": [
        MitreRef(tactic="command-and-control", technique_id="T1071",
                 technique_name="Application Layer Protocol",
                 url=f"{BASE_URL}/T1071"),
        MitreRef(tactic="command-and-control", technique_id="T1132",
                 technique_name="Data Encoding",
                 url=f"{BASE_URL}/T1132"),
    ],
    "c2_http": [
        MitreRef(tactic="command-and-control", technique_id="T1071",
                 technique_name="Application Layer Protocol",
                 subtechnique_id="T1071.001",
                 subtechnique_name="Web Protocols",
                 url=f"{BASE_URL}/T1071/001"),
    ],
    "c2_dns": [
        MitreRef(tactic="command-and-control", technique_id="T1071",
                 technique_name="Application Layer Protocol",
                 subtechnique_id="T1071.004",
                 subtechnique_name="DNS",
                 url=f"{BASE_URL}/T1071/004"),
    ],
    # Lateral Movement
    "lateral_movement": [
        MitreRef(tactic="lateral-movement", technique_id="T1021",
                 technique_name="Remote Services",
                 url=f"{BASE_URL}/T1021"),
    ],
    "smb_lateral": [
        MitreRef(tactic="lateral-movement", technique_id="T1021",
                 technique_name="Remote Services",
                 subtechnique_id="T1021.002",
                 subtechnique_name="SMB/Windows Admin Shares",
                 url=f"{BASE_URL}/T1021/002"),
    ],
    "rdp_lateral": [
        MitreRef(tactic="lateral-movement", technique_id="T1021",
                 technique_name="Remote Services",
                 subtechnique_id="T1021.001",
                 subtechnique_name="Remote Desktop Protocol",
                 url=f"{BASE_URL}/T1021/001"),
    ],
    # Impact
    "dos_syn_flood": [
        MitreRef(tactic="impact", technique_id="T1499",
                 technique_name="Endpoint Denial of Service",
                 subtechnique_id="T1499.001",
                 subtechnique_name="OS Exhaustion Flood",
                 url=f"{BASE_URL}/T1499/001"),
    ],
    "dos_icmp_flood": [
        MitreRef(tactic="impact", technique_id="T1498",
                 technique_name="Network Denial of Service",
                 subtechnique_id="T1498.001",
                 subtechnique_name="Direct Network Flood",
                 url=f"{BASE_URL}/T1498/001"),
    ],
    # Defense Evasion
    "arp_spoofing": [
        MitreRef(tactic="credential-access", technique_id="T1557",
                 technique_name="Adversary-in-the-Middle",
                 subtechnique_id="T1557.002",
                 subtechnique_name="ARP Cache Poisoning",
                 url=f"{BASE_URL}/T1557/002"),
    ],
    "deprecated_tls": [
        MitreRef(tactic="collection", technique_id="T1040",
                 technique_name="Network Sniffing",
                 url=f"{BASE_URL}/T1040"),
    ],
    "ssh_v1": [
        MitreRef(tactic="credential-access", technique_id="T1557",
                 technique_name="Adversary-in-the-Middle",
                 url=f"{BASE_URL}/T1557"),
    ],
    # Discovery
    "dga_malware": [
        MitreRef(tactic="command-and-control", technique_id="T1568",
                 technique_name="Dynamic Resolution",
                 subtechnique_id="T1568.002",
                 subtechnique_name="Domain Generation Algorithms",
                 url=f"{BASE_URL}/T1568/002"),
    ],
    "nxdomain_storm": [
        MitreRef(tactic="command-and-control", technique_id="T1568",
                 technique_name="Dynamic Resolution",
                 url=f"{BASE_URL}/T1568"),
    ],
    # Exfiltration
    "data_exfil": [
        MitreRef(tactic="exfiltration", technique_id="T1041",
                 technique_name="Exfiltration Over C2 Channel",
                 url=f"{BASE_URL}/T1041"),
    ],
    # Suspicious tools
    "suspicious_ua": [
        MitreRef(tactic="discovery", technique_id="T1595",
                 technique_name="Active Scanning",
                 url=f"{BASE_URL}/T1595"),
    ],
}


def get_mitre(rule_category: str) -> List[MitreRef]:
    """Return MITRE ATT&CK references for a detection category."""
    return _DB.get(rule_category, [])
