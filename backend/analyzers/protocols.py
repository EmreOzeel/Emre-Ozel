"""
Additional protocol analyzers (ICMP, ARP, DHCP, SMTP, FTP, SSH, SMB, RDP,
Kerberos, LDAP, NTP, SNMP, QUIC, SIP).
Operates on normalized PacketRecord extras dict.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from detection.engine import build_finding
from models import CaptureContext, Confidence, Evidence, Severity, TimelineEvent

_DHCP_TYPES = {
    "1": "DISCOVER", "2": "OFFER", "3": "REQUEST", "4": "DECLINE",
    "5": "ACK", "6": "NAK", "7": "RELEASE", "8": "INFORM",
}


def analyze(ctx: CaptureContext) -> None:
    # Per-protocol counters
    icmp_type_counts: Dict[str, int] = defaultdict(int)
    arp_requests = arp_replies = 0
    gratuitous_count = 0
    dhcp_type_counts: Dict[str, int] = defaultdict(int)
    dhcp_assignments: List[Dict] = []
    smtp_commands: Dict[str, int] = defaultdict(int)
    smtp_auth_plain = 0
    ftp_commands: Dict[str, int] = defaultdict(int)
    ftp_cred_count = 0
    ssh_versions: Dict[str, int] = defaultdict(int)
    ssh_v1_instances: List[Dict] = []
    smb1_cmds: Dict[str, int] = defaultdict(int)
    smb2_cmds: Dict[str, int] = defaultdict(int)
    rdp_count = 0
    kerb_types: Dict[str, int] = defaultdict(int)
    kerb_errors = 0
    ldap_count = 0
    ntp_modes: Dict[str, int] = defaultdict(int)
    snmp_versions: Dict[str, int] = defaultdict(int)
    snmp_insecure = 0
    quic_versions: Dict[str, int] = defaultdict(int)
    sip_methods: Dict[str, int] = defaultdict(int)
    sip_status: Dict[str, int] = defaultdict(int)

    for pkt in ctx.packets:
        raw = pkt.extras
        src, dst = pkt.src_ip, pkt.dst_ip
        ts = pkt.ts

        # ICMP
        if pkt.has_icmp:
            t = raw.get("icmp.type", "")
            _names = {"0": "Echo Reply", "3": "Unreachable", "8": "Echo Request", "11": "TTL Exceeded"}
            icmp_type_counts[_names.get(t, f"Type {t}")] += 1
            if t == "3":
                ctx.timeline.append(TimelineEvent(
                    ts=ts, event_type="icmp_unreachable",
                    src_ip=src, dst_ip=dst,
                    label=f"ICMP Unreachable: {src}→{dst}",
                    detail=f"ICMP Unreachable code={raw.get('icmp.code','')} from {src}",
                    severity=Severity.INFO, protocol="ICMP",
                ))

        # ARP
        if pkt.has_arp:
            op = raw.get("arp.opcode", "")
            if op == "1":
                arp_requests += 1
            elif op == "2":
                arp_replies += 1
                s_ip = raw.get("arp.src.proto_ipv4", "")
                t_ip = raw.get("arp.dst.proto_ipv4", "")
                if s_ip and s_ip == t_ip:
                    gratuitous_count += 1

        # DHCP
        if pkt.has_dhcp:
            mtype = raw.get("dhcp.option.dhcp", "")
            if mtype:
                dhcp_type_counts[_DHCP_TYPES.get(mtype, f"Type{mtype}")] += 1
            if mtype == "5":   # ACK
                assigned = raw.get("dhcp.ip.your", "")
                mac = raw.get("dhcp.hw.mac_addr", "")
                if assigned:
                    dhcp_assignments.append({"ip": assigned, "mac": mac, "server": src, "ts": ts})
                    ctx.timeline.append(TimelineEvent(
                        ts=ts, event_type="dhcp_ack",
                        src_ip=src, dst_ip=dst,
                        label=f"DHCP ACK: {assigned}",
                        detail=f"{src} assigned {assigned} to {mac or 'unknown'}",
                        severity=Severity.INFO, protocol="DHCP",
                    ))

        # SMTP
        cmd = raw.get("smtp.req.command", "").upper()
        if cmd:
            smtp_commands[cmd] += 1
            if cmd in ("AUTH", "AUTH PLAIN", "AUTH LOGIN"):
                smtp_auth_plain += 1

        # FTP
        fcmd = raw.get("ftp.request.command", "").upper()
        if fcmd:
            ftp_commands[fcmd] += 1
            if fcmd in ("USER", "PASS"):
                ftp_cred_count += 1

        # SSH
        sproto = raw.get("ssh.protocol", "")
        if sproto:
            ssh_versions[sproto] += 1
            if sproto.startswith("SSH-1"):
                ssh_v1_instances.append({"src": src, "dst": dst, "version": sproto, "ts": ts})

        # SMB
        if raw.get("smb.cmd"):
            smb1_cmds[raw["smb.cmd"]] += 1
        if raw.get("smb2.cmd"):
            smb2_cmds[raw["smb2.cmd"]] += 1

        # RDP
        if raw.get("rdp.neg_req.selectedProtocol"):
            rdp_count += 1
            ctx.timeline.append(TimelineEvent(
                ts=ts, event_type="rdp_connect",
                src_ip=src, dst_ip=dst,
                label=f"RDP: {src}→{dst}",
                detail=f"RDP connection attempt {src}→{dst}",
                severity=Severity.INFO, protocol="RDP",
            ))

        # Kerberos
        ktype = raw.get("kerberos.msg_type", "")
        if ktype:
            _knames = {"10": "AS-REQ", "11": "AS-REP", "12": "TGS-REQ", "13": "TGS-REP",
                       "14": "AP-REQ", "15": "AP-REP", "30": "KRB-ERROR"}
            kerb_types[_knames.get(ktype, f"Type{ktype}")] += 1
            if ktype == "30":
                kerb_errors += 1

        # LDAP
        if raw.get("ldap.requestName"):
            ldap_count += 1

        # NTP
        nmode = raw.get("ntp.mode", "")
        if nmode:
            ntp_modes[nmode] += 1

        # SNMP
        sver = raw.get("snmp.version", "")
        if sver:
            snmp_versions[sver] += 1
            if sver in ("0", "1"):   # v1, v2c
                snmp_insecure += 1

        # QUIC
        qver = raw.get("quic.version", "")
        if qver:
            quic_versions[qver] += 1

        # SIP
        sm = raw.get("sip.Method", "")
        if sm:
            sip_methods[sm] += 1
        ss = raw.get("sip.Status-Code", "")
        if ss:
            sip_status[ss] += 1

    # ── Build findings ─────────────────────────────────────────────────────────

    if ftp_cred_count >= 2:
        ctx.findings.append(build_finding(
            rule_id="PROTO-001",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            category="protocols",
            title=f"FTP Cleartext Credentials — {ftp_cred_count} Commands",
            description=f"{ftp_cred_count} FTP USER/PASS commands captured in plaintext.",
            explanation=(
                "FTP transmits credentials in the clear. Any network observer between "
                "client and server can read usernames and passwords trivially."
            ),
            possible_causes=["Legacy FTP service without encryption"],
            recommended_actions=[
                "Replace FTP with SFTP (SSH) or FTPS (FTP over TLS)",
                "If FTP must remain, restrict to trusted networks only",
            ],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(
                metrics={"ftp_cred_commands": ftp_cred_count,
                         "ftp_commands": dict(ftp_commands)},
            ),
            mitre_keys=["cleartext_creds_ftp"],
        ))

    if ssh_v1_instances:
        ctx.findings.append(build_finding(
            rule_id="PROTO-002",
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            category="protocols",
            title=f"SSHv1 Protocol Detected ({len(ssh_v1_instances)} sessions)",
            description=f"{len(ssh_v1_instances)} SSH connections using broken SSHv1.",
            explanation=(
                "SSH protocol version 1 has known cryptographic weaknesses including "
                "susceptibility to man-in-the-middle attacks. Only SSHv2 should be used."
            ),
            possible_causes=["Unpatched legacy SSH servers or clients"],
            recommended_actions=[
                "Add 'Protocol 2' to /etc/ssh/sshd_config on all SSH servers",
                "Audit and upgrade legacy SSH clients",
            ],
            affected_hosts=list({i["src"] for i in ssh_v1_instances} |
                                {i["dst"] for i in ssh_v1_instances}),
            affected_flows=[],
            evidence=Evidence(
                metrics={"sshv1_sessions": len(ssh_v1_instances)},
                samples=[f"{i['src']}→{i['dst']} ({i['version']})"
                         for i in ssh_v1_instances[:5]],
            ),
            mitre_keys=["ssh_v1"],
        ))

    if snmp_insecure >= 5:
        ctx.findings.append(build_finding(
            rule_id="PROTO-003",
            severity=Severity.MEDIUM, confidence=Confidence.HIGH,
            category="protocols",
            title=f"SNMP v1/v2c — Cleartext Community Strings ({snmp_insecure} packets)",
            description=f"{snmp_insecure} SNMP packets using v1/v2c with cleartext community strings.",
            explanation=(
                "SNMP v1 and v2c transmit community strings (effectively passwords) in plaintext. "
                "Community strings can be sniffed and used to read/write MIB variables, "
                "potentially exposing full network topology and configuration."
            ),
            possible_causes=["Network devices using legacy SNMP configuration"],
            recommended_actions=[
                "Upgrade all SNMP to v3 with authPriv security level",
                "Use strong authentication (SHA) and encryption (AES)",
                "Restrict SNMP access to management VLANs only",
            ],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(metrics={"snmp_insecure_packets": snmp_insecure,
                                       "versions": dict(snmp_versions)}),
            mitre_keys=[],
        ))

    if kerb_errors >= 10:
        ctx.findings.append(build_finding(
            rule_id="PROTO-004",
            severity=Severity.MEDIUM, confidence=Confidence.LOW,
            category="protocols",
            title=f"Kerberos Errors — {kerb_errors} KRB-ERROR Messages",
            description=f"{kerb_errors} Kerberos error responses detected.",
            explanation=(
                "High Kerberos error rates may indicate password spraying, Kerberoasting, "
                "AS-REP roasting, or simply misconfigured accounts. "
                "Kerberoasting (T1558.003) involves requesting TGS tickets for service "
                "accounts to crack offline."
            ),
            possible_causes=[
                "Password brute-force or spraying against domain accounts",
                "Kerberoasting attack targeting service account SPNs",
                "Expired or misconfigured service account credentials",
                "Clock skew exceeding 5 minutes between DC and client",
            ],
            recommended_actions=[
                "Enable AD audit logs and alert on KRB-ERROR events",
                "Use long, random passwords for service accounts",
                "Consider Protected Users security group for privileged accounts",
                "Verify NTP synchronization across domain members",
            ],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(metrics={"krb_errors": kerb_errors,
                                       "message_types": dict(kerb_types)}),
            mitre_keys=["kerberoasting"],
        ))

    if smtp_auth_plain >= 1:
        ctx.findings.append(build_finding(
            rule_id="PROTO-005",
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            category="protocols",
            title=f"SMTP Plaintext Authentication ({smtp_auth_plain} auth attempts)",
            description=f"{smtp_auth_plain} SMTP AUTH PLAIN/LOGIN commands detected.",
            explanation=(
                "SMTP AUTH PLAIN and AUTH LOGIN encode credentials in base64 (not encrypted). "
                "If the SMTP session is not TLS-protected, credentials are exposed. "
                "Even with STARTTLS, verify the upgrade is happening."
            ),
            possible_causes=["Mail client not enforcing TLS before authentication"],
            recommended_actions=[
                "Enforce STARTTLS before AUTH (require_tls in Postfix)",
                "Use SMTPS on port 465 (implicit TLS) instead of port 587",
                "Audit mail client configurations for TLS enforcement",
            ],
            affected_hosts=[],
            affected_flows=[],
            evidence=Evidence(metrics={"smtp_auth_count": smtp_auth_plain,
                                       "commands": dict(smtp_commands)}),
            mitre_keys=[],
        ))

    # Store protocol stats for serialization
    ctx.protocol_details = {
        "icmp": {"type_counts": dict(icmp_type_counts)},
        "arp": {"requests": arp_requests, "replies": arp_replies, "gratuitous": gratuitous_count},
        "dhcp": {"type_counts": dict(dhcp_type_counts), "assignments": dhcp_assignments[:50]},
        "smtp": {"command_counts": dict(smtp_commands), "auth_plain_count": smtp_auth_plain},
        "ftp": {"command_counts": dict(ftp_commands), "cleartext_cred_count": ftp_cred_count},
        "ssh": {"version_counts": dict(ssh_versions), "v1_count": len(ssh_v1_instances)},
        "smb": {"smb1_commands": dict(smb1_cmds), "smb2_commands": dict(smb2_cmds)},
        "rdp": {"connection_count": rdp_count},
        "kerberos": {"message_counts": dict(kerb_types), "error_count": kerb_errors},
        "ldap": {"request_count": ldap_count},
        "ntp": {"mode_counts": dict(ntp_modes)},
        "snmp": {"version_counts": dict(snmp_versions), "insecure_count": snmp_insecure},
        "quic": {"version_counts": dict(quic_versions), "total": sum(quic_versions.values())},
        "sip": {"method_counts": dict(sip_methods), "status_counts": dict(sip_status)},
    }
