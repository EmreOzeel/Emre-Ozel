"""Additional protocol analyzers: ICMP, ARP, DHCP, SMTP, FTP, SSH, SMB, RDP, Kerberos, LDAP, SIP, NTP, SNMP, QUIC."""
from collections import defaultdict
from typing import List, Dict, Any


ICMP_TYPES = {
    "0": "Echo Reply", "3": "Dest Unreachable", "4": "Source Quench",
    "5": "Redirect", "8": "Echo Request", "9": "Router Advertisement",
    "11": "Time Exceeded", "12": "Parameter Problem", "13": "Timestamp",
}

DHCP_MSG_TYPES = {
    "1": "DISCOVER", "2": "OFFER", "3": "REQUEST", "4": "DECLINE",
    "5": "ACK", "6": "NAK", "7": "RELEASE", "8": "INFORM",
}

SMB2_COMMANDS = {
    "0": "NEGOTIATE", "1": "SESSION_SETUP", "2": "LOGOFF", "3": "TREE_CONNECT",
    "4": "TREE_DISCONNECT", "5": "CREATE", "6": "CLOSE", "7": "FLUSH",
    "8": "READ", "9": "WRITE", "10": "LOCK", "11": "IOCTL",
    "14": "FIND", "16": "GETINFO", "17": "SETINFO", "18": "CHANGE_NOTIFY",
}

KERBEROS_MSG_TYPES = {
    "10": "AS-REQ", "11": "AS-REP", "12": "TGS-REQ", "13": "TGS-REP",
    "14": "AP-REQ", "15": "AP-REP", "30": "KRB-ERROR",
}


def analyze(packets: List[Dict]) -> Dict[str, Any]:
    issues = []
    timeline_events = []

    # ICMP
    icmp_type_counts: Dict[str, int] = defaultdict(int)
    icmp_unreachable: List[Dict] = []

    # ARP
    arp_requests = 0
    arp_replies = 0
    gratuitous_arps: List[Dict] = []

    # DHCP
    dhcp_events: List[Dict] = []
    dhcp_type_counts: Dict[str, int] = defaultdict(int)

    # SMTP
    smtp_commands: Dict[str, int] = defaultdict(int)
    smtp_auth_plain = 0

    # FTP
    ftp_commands: Dict[str, int] = defaultdict(int)
    ftp_cleartext_creds = 0

    # SSH
    ssh_versions: Dict[str, int] = defaultdict(int)
    ssh_old_versions: List[Dict] = []

    # SMB
    smb_commands: Dict[str, int] = defaultdict(int)
    smb2_commands: Dict[str, int] = defaultdict(int)

    # RDP
    rdp_connections: List[Dict] = []

    # Kerberos
    kerb_msg_counts: Dict[str, int] = defaultdict(int)
    kerb_errors = 0

    # LDAP
    ldap_requests: List[Dict] = []

    # SIP
    sip_methods: Dict[str, int] = defaultdict(int)
    sip_status: Dict[str, int] = defaultdict(int)

    # NTP
    ntp_modes: Dict[str, int] = defaultdict(int)
    ntp_strata: Dict[str, int] = defaultdict(int)

    # SNMP
    snmp_versions: Dict[str, int] = defaultdict(int)
    snmp_v1_v2_count = 0

    # QUIC
    quic_versions: Dict[str, int] = defaultdict(int)

    for pkt in packets:
        ts_str = pkt.get("frame.time_epoch", "0")
        try:
            ts = float(ts_str)
        except ValueError:
            ts = 0.0

        src_ip = pkt.get("ip.src", pkt.get("ipv6.src", ""))
        dst_ip = pkt.get("ip.dst", pkt.get("ipv6.dst", ""))

        # ── ICMP ─────────────────────────────────────────────────────────────
        if "icmp.type" in pkt:
            icmp_type = pkt.get("icmp.type", "")
            icmp_code = pkt.get("icmp.code", "")
            type_name = ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")
            icmp_type_counts[type_name] += 1

            if icmp_type == "3":
                icmp_unreachable.append({
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "code": icmp_code, "ts": ts,
                })
                timeline_events.append({
                    "ts": ts, "type": "icmp_unreachable",
                    "label": f"ICMP Unreachable: {src_ip} → {dst_ip}",
                    "detail": f"ICMP Destination Unreachable code={icmp_code} from {src_ip}",
                    "severity": "warning",
                })

        # ── ARP ──────────────────────────────────────────────────────────────
        if "arp.opcode" in pkt:
            opcode = pkt.get("arp.opcode", "")
            sender_ip = pkt.get("arp.src.proto_ipv4", "")
            target_ip = pkt.get("arp.dst.proto_ipv4", "")
            if opcode == "1":
                arp_requests += 1
            elif opcode == "2":
                arp_replies += 1
                # Gratuitous ARP: sender == target
                if sender_ip and sender_ip == target_ip:
                    gratuitous_arps.append({
                        "ip": sender_ip,
                        "mac": pkt.get("arp.src.hw_mac", ""),
                        "ts": ts,
                    })

        # ── DHCP ─────────────────────────────────────────────────────────────
        if "dhcp.option.dhcp" in pkt:
            msg_type = pkt.get("dhcp.option.dhcp", "")
            msg_name = DHCP_MSG_TYPES.get(msg_type, f"Type {msg_type}")
            dhcp_type_counts[msg_name] += 1
            assigned_ip = pkt.get("dhcp.ip.your", "")
            if assigned_ip and msg_type == "5":   # ACK
                dhcp_events.append({
                    "type": "ACK", "assigned_ip": assigned_ip,
                    "src_ip": src_ip, "ts": ts,
                })
                timeline_events.append({
                    "ts": ts, "type": "dhcp_ack",
                    "label": f"DHCP ACK: {assigned_ip}",
                    "detail": f"DHCP server {src_ip} assigned {assigned_ip}",
                    "severity": "info",
                })

        # ── SMTP ─────────────────────────────────────────────────────────────
        if "smtp.req.command" in pkt:
            cmd = pkt.get("smtp.req.command", "").upper()
            smtp_commands[cmd] += 1
            if cmd in ("AUTH", "AUTH PLAIN", "AUTH LOGIN"):
                smtp_auth_plain += 1
                timeline_events.append({
                    "ts": ts, "type": "smtp_auth",
                    "label": f"SMTP Auth: {src_ip} → {dst_ip}",
                    "detail": f"Cleartext SMTP auth command from {src_ip}",
                    "severity": "warning",
                })

        # ── FTP ──────────────────────────────────────────────────────────────
        if "ftp.request.command" in pkt:
            cmd = pkt.get("ftp.request.command", "").upper()
            ftp_commands[cmd] += 1
            if cmd in ("USER", "PASS"):
                ftp_cleartext_creds += 1

        # ── SSH ──────────────────────────────────────────────────────────────
        if "ssh.protocol" in pkt:
            proto = pkt.get("ssh.protocol", "")
            ssh_versions[proto] += 1
            if proto.startswith("SSH-1"):
                ssh_old_versions.append({
                    "src_ip": src_ip, "dst_ip": dst_ip,
                    "version": proto, "ts": ts,
                })

        # ── SMB ──────────────────────────────────────────────────────────────
        if "smb.cmd" in pkt:
            smb_commands[pkt.get("smb.cmd", "")] += 1
        if "smb2.cmd" in pkt:
            cmd = pkt.get("smb2.cmd", "")
            cmd_name = SMB2_COMMANDS.get(cmd, f"CMD-{cmd}")
            smb2_commands[cmd_name] += 1

        # ── RDP ──────────────────────────────────────────────────────────────
        if "rdp.neg_req.selectedProtocol" in pkt:
            proto = pkt.get("rdp.neg_req.selectedProtocol", "")
            rdp_connections.append({
                "src_ip": src_ip, "dst_ip": dst_ip,
                "protocol": proto, "ts": ts,
            })
            timeline_events.append({
                "ts": ts, "type": "rdp_connect",
                "label": f"RDP: {src_ip} → {dst_ip}",
                "detail": f"RDP connection attempt from {src_ip} to {dst_ip}",
                "severity": "info",
            })

        # ── Kerberos ──────────────────────────────────────────────────────────
        if "kerberos.msg_type" in pkt:
            msg_type = pkt.get("kerberos.msg_type", "")
            msg_name = KERBEROS_MSG_TYPES.get(msg_type, f"Type {msg_type}")
            kerb_msg_counts[msg_name] += 1
            if msg_type == "30":
                kerb_errors += 1

        # ── LDAP ─────────────────────────────────────────────────────────────
        if "ldap.requestName" in pkt:
            ldap_requests.append({
                "src_ip": src_ip, "dst_ip": dst_ip,
                "request": pkt.get("ldap.requestName", ""), "ts": ts,
            })

        # ── SIP ───────────────────────────────────────────────────────────────
        if "sip.Method" in pkt:
            sip_methods[pkt.get("sip.Method", "")] += 1
        if "sip.Status-Code" in pkt:
            sip_status[pkt.get("sip.Status-Code", "")] += 1

        # ── NTP ───────────────────────────────────────────────────────────────
        if "ntp.mode" in pkt:
            ntp_modes[pkt.get("ntp.mode", "")] += 1
        if "ntp.stratum" in pkt:
            ntp_strata[pkt.get("ntp.stratum", "")] += 1

        # ── SNMP ──────────────────────────────────────────────────────────────
        if "snmp.version" in pkt:
            ver = pkt.get("snmp.version", "")
            snmp_versions[ver] += 1
            if ver in ("0", "1"):   # v1 or v2c (community string in plaintext)
                snmp_v1_v2_count += 1

        # ── QUIC ──────────────────────────────────────────────────────────────
        if "quic.version" in pkt:
            quic_versions[pkt.get("quic.version", "")] += 1

    # ── Build issues ──────────────────────────────────────────────────────────
    if ftp_cleartext_creds >= 2:
        issues.append({
            "severity": "critical", "category": "protocols",
            "title": "FTP Credentials Transmitted in Cleartext",
            "description": (
                f"FTP USER/PASS commands detected — credentials are being transmitted "
                f"in plaintext over the network. FTP has no encryption; use SFTP or FTPS instead. "
                f"{ftp_cleartext_creds} credential-related FTP commands captured."
            ),
            "count": ftp_cleartext_creds,
        })

    if ssh_old_versions:
        issues.append({
            "severity": "critical", "category": "protocols",
            "title": f"SSHv1 Detected — Insecure Protocol",
            "description": (
                f"{len(ssh_old_versions)} SSH connections using SSHv1, which is cryptographically broken "
                "and vulnerable to man-in-the-middle attacks. All SSH should use protocol version 2."
            ),
            "count": len(ssh_old_versions),
        })

    if snmp_v1_v2_count >= 5:
        issues.append({
            "severity": "warning", "category": "protocols",
            "title": f"SNMP v1/v2c in Use — Cleartext Community Strings",
            "description": (
                f"{snmp_v1_v2_count} SNMP packets using v1 or v2c, which transmit community strings "
                "(essentially passwords) in plaintext. Use SNMPv3 with authentication and encryption."
            ),
            "count": snmp_v1_v2_count,
        })

    if smtp_auth_plain >= 1:
        issues.append({
            "severity": "warning", "category": "protocols",
            "title": f"SMTP Plaintext Authentication",
            "description": (
                f"{smtp_auth_plain} SMTP AUTH PLAIN/LOGIN commands detected. "
                "Email credentials may be exposed if connection is not TLS-encrypted. "
                "Verify SMTP connections use STARTTLS or SMTPS (port 465)."
            ),
            "count": smtp_auth_plain,
        })

    if kerb_errors >= 10:
        issues.append({
            "severity": "warning", "category": "protocols",
            "title": f"Kerberos Errors — Possible Brute Force or Misconfiguration",
            "description": (
                f"{kerb_errors} Kerberos KRB-ERROR messages detected. "
                "High Kerberos error counts may indicate password spraying, brute-force attacks, "
                "or domain authentication misconfigurations."
            ),
            "count": kerb_errors,
        })

    if len(rdp_connections) >= 20:
        unique_srcs = len({r["src_ip"] for r in rdp_connections})
        issues.append({
            "severity": "warning", "category": "protocols",
            "title": f"Excessive RDP Connection Attempts ({len(rdp_connections)})",
            "description": (
                f"{len(rdp_connections)} RDP connection attempts from {unique_srcs} source(s). "
                "High RDP activity may indicate brute-force attacks or unauthorized remote access attempts."
            ),
            "count": len(rdp_connections),
        })

    return {
        "icmp": {
            "type_counts": dict(icmp_type_counts),
            "unreachable_count": len(icmp_unreachable),
        },
        "arp": {
            "requests": arp_requests,
            "replies": arp_replies,
            "gratuitous_count": len(gratuitous_arps),
        },
        "dhcp": {
            "type_counts": dict(dhcp_type_counts),
            "assignments": dhcp_events[:50],
        },
        "smtp": {
            "command_counts": dict(smtp_commands),
            "auth_plain_count": smtp_auth_plain,
        },
        "ftp": {
            "command_counts": dict(ftp_commands),
            "cleartext_cred_count": ftp_cleartext_creds,
        },
        "ssh": {
            "version_counts": dict(ssh_versions),
            "old_version_count": len(ssh_old_versions),
        },
        "smb": {
            "smb1_commands": dict(smb_commands),
            "smb2_commands": dict(smb2_commands),
        },
        "rdp": {
            "connection_count": len(rdp_connections),
        },
        "kerberos": {
            "message_counts": dict(kerb_msg_counts),
            "error_count": kerb_errors,
        },
        "ldap": {
            "request_count": len(ldap_requests),
        },
        "sip": {
            "method_counts": dict(sip_methods),
            "status_counts": dict(sip_status),
        },
        "ntp": {
            "mode_counts": dict(ntp_modes),
            "strata": dict(ntp_strata),
        },
        "snmp": {
            "version_counts": dict(snmp_versions),
            "insecure_count": snmp_v1_v2_count,
        },
        "quic": {
            "version_counts": dict(quic_versions),
            "total": sum(quic_versions.values()),
        },
        "issues": issues,
        "timeline_events": timeline_events[:200],
    }
