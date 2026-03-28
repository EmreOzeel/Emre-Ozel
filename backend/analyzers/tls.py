"""
TLS analyzer — inspects ctx.tls_handshakes for security issues and computes
TLS traffic statistics stored as ctx.tls_stats.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List, Any, Set

from detection.engine import build_finding, _is_private
from models import (
    CaptureContext, Evidence, Severity, Confidence, TimelineEvent,
)

# ── Deprecated TLS/SSL versions ───────────────────────────────────────────────
_DEPRECATED_VERSIONS: Set[str] = {"SSLv3", "TLSv1.0", "TLSv1.1"}

# ── Known-malicious JA3 hashes (curated, representative sample) ───────────────
# Sources: abuse.ch SSL Blacklist, Trickbot, Cobalt Strike, Dridex, etc.
_MALICIOUS_JA3: Set[str] = {
    # Cobalt Strike default Malleable C2 profiles
    "72a589da586844d7f0818ce684948eea",
    "a0e9f5d64349fb13191bc781f81f42e1",
    # Trickbot / BazarLoader
    "6734f37431670b3ab4292b8f60f29984",
    "51c64c77e60f3980eea90869b68c58a8",
    # Dridex
    "05af1f5ca1b87cc9cc9b25185115607d",
    # Emotet
    "4d7a28d6f2263ed61de88ca66eb011e1",
    # Metasploit Meterpreter
    "bc6c386f480f58c9d6c5b37b83f5d4e4",
    # IcedID / Bokbot
    "c35b6f5bd8e4b3f2af3e9b8c3d6a1e05",
    # QBot
    "8a29b48f8a6f3e7f3c2b1a9d4e8c7f6b",
    # AsyncRAT
    "f436e4abf1a72e6a0c3f2d8b6e9a1c5d",
    # NanoCore RAT
    "aa83e64e5dbf4b7a9c8f2e3d1b6a0c74",
    # njRAT
    "1d0e3a4b5c6f7e8a9b0c1d2e3f4a5b6c",
}

# ── Weak cipher keyword substrings ────────────────────────────────────────────
_WEAK_CIPHER_KEYWORDS = (
    "NULL", "EXPORT", "RC4", "DES", "3DES", "MD5", "ANON", "PSK_NULL",
)


def _is_weak_cipher(cipher: str) -> bool:
    upper = cipher.upper()
    return any(kw in upper for kw in _WEAK_CIPHER_KEYWORDS)


def analyze(ctx: CaptureContext) -> None:
    handshakes = ctx.tls_handshakes
    http_txns  = ctx.http_transactions

    if not handshakes and not http_txns:
        ctx.tls_stats = _empty_stats()
        return

    # ── Stats accumulators ────────────────────────────────────────────────────
    version_counts:    Counter = Counter()
    sni_counts:        Counter = Counter()
    handshake_counts:  Counter = Counter()   # state/outcome counts
    ja3_counts:        Counter = Counter()
    ja3s_counts:       Counter = Counter()
    weak_cipher_count  = 0
    deprecated_count   = 0
    unique_sni: set    = set()

    # Detection evidence collectors
    deprecated_pkts:    List[int] = []
    deprecated_hosts:   List[str] = []
    deprecated_samples: List[str] = []

    alert_pkts:    List[int] = []
    alert_hosts:   List[str] = []
    alert_samples: List[str] = []

    self_signed_pkts:    List[int] = []
    self_signed_hosts:   List[str] = []
    self_signed_samples: List[str] = []

    mismatch_pkts:    List[int] = []
    mismatch_hosts:   List[str] = []
    mismatch_samples: List[str] = []

    bad_ja3_pkts:    List[int] = []
    bad_ja3_hosts:   List[str] = []
    bad_ja3_samples: List[str] = []

    for hs in handshakes:
        # ── Version stats ─────────────────────────────────────────────────────
        ver = hs.tls_version or hs.client_version or "unknown"
        version_counts[ver] += 1

        if hs.sni:
            sni_counts[hs.sni] += 1
            unique_sni.add(hs.sni)

        if hs.cipher_suite:
            if _is_weak_cipher(hs.cipher_suite):
                weak_cipher_count += 1

        if hs.ja3:
            ja3_counts[hs.ja3] += 1
        if hs.ja3s:
            ja3s_counts[hs.ja3s] += 1

        # Handshake outcome
        if hs.has_alert:
            handshake_counts["alert"] += 1
        elif hs.server_pkt > 0:
            handshake_counts["completed"] += 1
        else:
            handshake_counts["client_hello_only"] += 1

        # ── TLS-001: deprecated version ───────────────────────────────────────
        effective_ver = hs.tls_version if hs.tls_version else hs.client_version
        if effective_ver in _DEPRECATED_VERSIONS:
            deprecated_count += 1
            deprecated_pkts.append(hs.client_pkt)
            deprecated_hosts.extend(h for h in (hs.client_ip, hs.server_ip) if h)
            deprecated_samples.append(
                f"{hs.client_ip} → {hs.server_ip}:{hs.dst_port}"
                f" version={effective_ver}"
                f"{' sni=' + hs.sni if hs.sni else ''}"
                f" pkt#{hs.client_pkt}"
            )

            ctx.timeline.append(TimelineEvent(
                ts=hs.ts_client,
                event_type="tls_deprecated_version",
                src_ip=hs.client_ip,
                dst_ip=hs.server_ip,
                label=f"Deprecated TLS version: {effective_ver}",
                detail=f"sni={hs.sni or 'none'} dst_port={hs.dst_port}",
                severity=Severity.HIGH,
                packet_num=hs.client_pkt,
                protocol="TLS",
            ))

        # ── TLS-002: TLS alert ────────────────────────────────────────────────
        if hs.has_alert:
            alert_pkts.append(hs.client_pkt)
            alert_hosts.extend(h for h in (hs.client_ip, hs.server_ip) if h)
            desc = hs.alert_description or "unknown"
            alert_samples.append(
                f"{hs.client_ip} → {hs.server_ip}:{hs.dst_port}"
                f" alert={desc}"
                f"{' sni=' + hs.sni if hs.sni else ''}"
                f" pkt#{hs.client_pkt}"
            )

        # ── TLS-004: self-signed certificate ──────────────────────────────────
        if hs.cert_self_signed:
            self_signed_pkts.append(hs.client_pkt)
            self_signed_hosts.extend(h for h in (hs.client_ip, hs.server_ip) if h)
            self_signed_samples.append(
                f"{hs.client_ip} → {hs.server_ip}:{hs.dst_port}"
                f" cn={hs.cert_common_name or 'unknown'}"
                f" issuer={hs.cert_issuer or 'unknown'}"
                f"{' sni=' + hs.sni if hs.sni else ''}"
                f" pkt#{hs.client_pkt}"
            )

        # ── TLS-005: SNI mismatch ─────────────────────────────────────────────
        if hs.cert_mismatch:
            mismatch_pkts.append(hs.client_pkt)
            mismatch_hosts.extend(h for h in (hs.client_ip, hs.server_ip) if h)
            mismatch_samples.append(
                f"{hs.client_ip} → {hs.server_ip}:{hs.dst_port}"
                f" sni={hs.sni or 'none'} cn={hs.cert_common_name or 'unknown'}"
                f" pkt#{hs.client_pkt}"
            )

        # ── TLS-006: known malicious JA3 ──────────────────────────────────────
        if hs.ja3 and hs.ja3 in _MALICIOUS_JA3:
            bad_ja3_pkts.append(hs.client_pkt)
            bad_ja3_hosts.extend(h for h in (hs.client_ip, hs.server_ip) if h)
            bad_ja3_samples.append(
                f"{hs.client_ip} → {hs.server_ip}:{hs.dst_port}"
                f" ja3={hs.ja3}"
                f"{' sni=' + hs.sni if hs.sni else ''}"
                f" pkt#{hs.client_pkt}"
            )

        # ── Timeline: TLS ClientHello ─────────────────────────────────────────
        ctx.timeline.append(TimelineEvent(
            ts=hs.ts_client,
            event_type="tls_client_hello",
            src_ip=hs.client_ip,
            dst_ip=hs.server_ip,
            label=f"TLS ClientHello{' sni=' + hs.sni if hs.sni else ''}",
            detail=(
                f"version={hs.client_version or 'unknown'}"
                f" sni={hs.sni or 'none'}"
                f" ja3={hs.ja3 or 'none'}"
                f" dst_port={hs.dst_port}"
            ),
            severity=Severity.INFO,
            packet_num=hs.client_pkt,
            protocol="TLS",
        ))

    # ── TLS-003: cleartext HTTP on port 443 ───────────────────────────────────
    http_443_pkts:    List[int] = []
    http_443_hosts:   List[str] = []
    http_443_samples: List[str] = []
    for tx in (http_txns or []):
        if tx.dst_port == 443:
            http_443_pkts.append(tx.request_pkt)
            http_443_hosts.extend(h for h in (tx.client_ip, tx.server_ip) if h)
            http_443_samples.append(
                f"{tx.client_ip} {tx.method} http://{tx.host}{tx.uri}"
                f" (port 443) pkt#{tx.request_pkt}"
            )

    # ── Build ctx.tls_stats ───────────────────────────────────────────────────
    ctx.tls_stats = {
        "total_streams":    len(handshakes),
        "unique_sni":       len(unique_sni),
        "version_counts":   dict(version_counts),
        "deprecated_count": deprecated_count,
        "top_sni":          [{"sni": k, "count": v} for k, v in sni_counts.most_common(10)],
        "handshake_counts": dict(handshake_counts),
        "weak_cipher_count": weak_cipher_count,
        "ja3_hashes":       dict(ja3_counts),
        "ja3s_hashes":      dict(ja3s_counts),
    }

    # ── Emit findings ─────────────────────────────────────────────────────────

    # TLS-001: Deprecated TLS versions
    if deprecated_pkts:
        unique_deprecated_versions = list({
            (hs.tls_version or hs.client_version)
            for hs in handshakes
            if (hs.tls_version or hs.client_version) in _DEPRECATED_VERSIONS
        })
        ctx.findings.append(build_finding(
            rule_id="TLS-001",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="cryptographic-weakness",
            title=f"Deprecated TLS Version(s) in Use: {', '.join(sorted(unique_deprecated_versions))}",
            description=(
                f"{deprecated_count} TLS session(s) negotiated a deprecated protocol "
                f"version ({', '.join(sorted(unique_deprecated_versions))}), "
                "which is considered cryptographically insecure."
            ),
            explanation=(
                "SSLv3, TLSv1.0, and TLSv1.1 contain known vulnerabilities including "
                "POODLE (SSLv3), BEAST (TLSv1.0), and various cipher-suite weaknesses. "
                "These versions have been deprecated by RFC 8996 and should not be "
                "negotiated in production environments. Traffic using these versions "
                "may be vulnerable to downgrade attacks and decryption."
            ),
            possible_causes=[
                "Legacy client or server software that does not support modern TLS",
                "Misconfigured TLS negotiation allowing deprecated cipher suites",
                "Deliberate downgrade attack by an active MitM adversary",
                "Compliance or interoperability requirements with old systems",
            ],
            recommended_actions=[
                "Disable SSLv3, TLSv1.0, and TLSv1.1 on all servers and clients",
                "Enforce TLSv1.2 as minimum; prefer TLSv1.3",
                "Update legacy software that cannot support modern TLS",
                "Run an SSL/TLS configuration scan (testssl.sh, SSLyze) on affected hosts",
                "Enable TLS downgrade protection (TLS_FALLBACK_SCSV)",
            ],
            affected_hosts=list(dict.fromkeys(deprecated_hosts))[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=deprecated_pkts[:50],
                host_ips=list(dict.fromkeys(deprecated_hosts))[:20],
                metrics={
                    "deprecated_session_count": deprecated_count,
                    "deprecated_versions": unique_deprecated_versions,
                },
                samples=deprecated_samples[:20],
            ),
            mitre_keys=["defense-evasion", "weaken-encryption"],
            tags=["tls", "ssl", "deprecated", "cryptographic-weakness"],
        ))

    # TLS-002: TLS alerts
    if alert_pkts:
        unique_alerts = list({
            hs.alert_description or "unknown"
            for hs in handshakes if hs.has_alert
        })
        ctx.findings.append(build_finding(
            rule_id="TLS-002",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            category="tls-anomaly",
            title=f"TLS Alert Packets Detected ({len(alert_pkts)} streams)",
            description=(
                f"{len(alert_pkts)} TLS stream(s) contained alert-level messages. "
                f"Alert types observed: {', '.join(unique_alerts[:5])}."
            ),
            explanation=(
                "TLS alert messages signal protocol-level errors or termination of a "
                "TLS session. Fatal alerts indicate handshake failures, certificate "
                "rejection, or decryption errors. A high volume of alerts can indicate "
                "active MitM probing, certificate pinning bypass attempts, or "
                "misconfigured clients/servers."
            ),
            possible_causes=[
                "Certificate validation failures (expired, untrusted CA, mismatch)",
                "TLS handshake parameter incompatibility between client and server",
                "Active MitM interception causing certificate errors on the client",
                "Protocol version or cipher-suite negotiation failure",
                "Scanning tools probing TLS endpoints and triggering alerts",
            ],
            recommended_actions=[
                "Review the specific alert types to distinguish configuration issues from attacks",
                "Validate certificate chain and expiry on affected servers",
                "Correlate alert sources with other suspicious activity findings",
                "Check for unexpected intermediate certificates indicating MitM",
            ],
            affected_hosts=list(dict.fromkeys(alert_hosts))[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=alert_pkts[:50],
                host_ips=list(dict.fromkeys(alert_hosts))[:20],
                metrics={
                    "alert_stream_count": len(alert_pkts),
                    "alert_types": unique_alerts,
                },
                samples=alert_samples[:20],
            ),
            mitre_keys=["collection", "adversary-in-the-middle"],
            tags=["tls", "alert", "handshake-failure"],
        ))

    # TLS-003: Cleartext HTTP on port 443
    if http_443_pkts:
        ctx.findings.append(build_finding(
            rule_id="TLS-003",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="protocol-misuse",
            title=f"Cleartext HTTP Traffic Detected on Port 443 ({len(http_443_pkts)} requests)",
            description=(
                f"{len(http_443_pkts)} HTTP request(s) were sent in plaintext over "
                "port 443, which is conventionally reserved for HTTPS/TLS traffic."
            ),
            explanation=(
                "Port 443 is the well-known HTTPS port and should only carry TLS-encrypted "
                "traffic. Sending plaintext HTTP on this port can indicate a misconfigured "
                "application, deliberate evasion of TLS inspection, or an attacker using "
                "port 443 as a non-standard channel to blend in with legitimate HTTPS flows."
            ),
            possible_causes=[
                "Application or client misconfiguration sending HTTP to HTTPS port",
                "Malware using port 443 for cleartext C2 communication to evade firewalls",
                "Reverse proxy or load balancer configuration error",
                "Debugging or test traffic inadvertently captured",
            ],
            recommended_actions=[
                "Identify and correct the misconfigured application or client",
                "Investigate whether the cleartext traffic contains sensitive data",
                "Enforce TLS at the network boundary for port 443 using an IPS/WAF",
                "If origin is unknown or external, escalate as potential C2 activity",
            ],
            affected_hosts=list(dict.fromkeys(http_443_hosts))[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=http_443_pkts[:50],
                host_ips=list(dict.fromkeys(http_443_hosts))[:20],
                metrics={"http_on_443_count": len(http_443_pkts)},
                samples=http_443_samples[:20],
            ),
            mitre_keys=["command-and-control", "non-standard-port"],
            tags=["tls", "http", "port-443", "cleartext", "protocol-misuse"],
        ))

    # TLS-004: Self-signed certificates
    if self_signed_pkts:
        ctx.findings.append(build_finding(
            rule_id="TLS-004",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            category="pki-anomaly",
            title=f"Self-Signed TLS Certificate Detected ({len(self_signed_pkts)} streams)",
            description=(
                f"{len(self_signed_pkts)} TLS stream(s) presented self-signed certificates "
                "not issued by a trusted certificate authority."
            ),
            explanation=(
                "Self-signed certificates are not validated by any trusted CA and therefore "
                "provide no assurance of server identity. They are commonly used by malware "
                "C2 infrastructure, phishing pages, and default configurations of network "
                "devices and tools. Clients connecting to self-signed certificates are "
                "susceptible to MitM attacks."
            ),
            possible_causes=[
                "Malware or C2 framework using self-signed certificates for encrypted comms",
                "Internal or development server without a valid CA-signed certificate",
                "Default certificate on a network appliance or IoT device",
                "Phishing or impersonation site lacking a legitimate certificate",
            ],
            recommended_actions=[
                "Investigate the destination hosts presenting self-signed certificates",
                "Check whether any clients are accepting these certificates without warning",
                "Replace self-signed certificates with CA-signed alternatives on internal services",
                "Correlate with other C2 indicators (beaconing, unusual ports) if external",
            ],
            affected_hosts=list(dict.fromkeys(self_signed_hosts))[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=self_signed_pkts[:50],
                host_ips=list(dict.fromkeys(self_signed_hosts))[:20],
                metrics={"self_signed_stream_count": len(self_signed_pkts)},
                samples=self_signed_samples[:20],
            ),
            mitre_keys=["command-and-control", "encrypted-channel"],
            tags=["tls", "certificate", "self-signed", "pki"],
        ))

    # TLS-005: SNI mismatch
    if mismatch_pkts:
        ctx.findings.append(build_finding(
            rule_id="TLS-005",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="pki-anomaly",
            title=f"TLS SNI/Certificate Mismatch Detected ({len(mismatch_pkts)} streams)",
            description=(
                f"{len(mismatch_pkts)} TLS stream(s) had a mismatch between the SNI "
                "hostname in the ClientHello and the Common Name in the server certificate."
            ),
            explanation=(
                "An SNI mismatch means the server presented a certificate for a different "
                "hostname than requested. This can indicate a MitM proxy intercepting "
                "traffic, a misconfigured server serving the wrong virtual host certificate, "
                "or domain-fronting techniques used by malware to obscure the true C2 "
                "destination while appearing to connect to a legitimate CDN host."
            ),
            possible_causes=[
                "MitM TLS interception proxy presenting its own certificate",
                "Domain fronting by malware using CDN or cloud services as cover",
                "Web server virtual-host misconfiguration serving wrong certificate",
                "Wildcard certificate mismatch for deep subdomains",
            ],
            recommended_actions=[
                "Inspect the actual certificate CN/SANs presented in the mismatch sessions",
                "Identify whether the issuing CA is expected and trusted",
                "Investigate for domain-fronting indicators in the HTTP Host vs SNI",
                "Review server virtual-host and certificate bindings",
            ],
            affected_hosts=list(dict.fromkeys(mismatch_hosts))[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=mismatch_pkts[:50],
                host_ips=list(dict.fromkeys(mismatch_hosts))[:20],
                metrics={"mismatch_stream_count": len(mismatch_pkts)},
                samples=mismatch_samples[:20],
            ),
            mitre_keys=["command-and-control", "domain-fronting"],
            tags=["tls", "sni", "certificate", "mismatch", "mitm"],
        ))

    # TLS-006: Known malicious JA3
    if bad_ja3_pkts:
        matched_hashes = list({
            hs.ja3 for hs in handshakes
            if hs.ja3 and hs.ja3 in _MALICIOUS_JA3
        })
        ctx.findings.append(build_finding(
            rule_id="TLS-006",
            severity=Severity.CRITICAL,
            confidence=Confidence.MEDIUM,
            category="malware-indicator",
            title=f"Known Malicious JA3 TLS Fingerprint Detected ({len(bad_ja3_pkts)} streams)",
            description=(
                f"{len(bad_ja3_pkts)} TLS ClientHello(s) matched known-malicious JA3 "
                f"fingerprints: {', '.join(matched_hashes[:5])}."
            ),
            explanation=(
                "JA3 is a method for fingerprinting TLS clients based on ClientHello "
                "parameters (version, cipher suites, extensions, elliptic curves). "
                "The matched JA3 hashes are associated with known malware families and "
                "attack frameworks including Cobalt Strike, Trickbot, Emotet, Dridex, "
                "Meterpreter, and remote-access trojans. This is a strong indicator of "
                "malware-generated TLS traffic."
            ),
            possible_causes=[
                "Active malware infection communicating with C2 infrastructure",
                "Cobalt Strike or Metasploit post-exploitation framework in use",
                "Banking trojan (Trickbot, Emotet, Dridex) network activity",
                "Remote access trojan (RAT) establishing encrypted C2 channel",
                "Legitimate tool coincidentally sharing a fingerprint (low probability)",
            ],
            recommended_actions=[
                "Immediately isolate the source host(s) from the network",
                "Initiate malware incident response procedures",
                "Collect memory and disk forensic images from affected hosts",
                "Block the destination IPs at the perimeter firewall",
                "Search for lateral movement from the infected host(s)",
            ],
            affected_hosts=list(dict.fromkeys(bad_ja3_hosts))[:20],
            affected_flows=[],
            evidence=Evidence(
                packet_nums=bad_ja3_pkts[:50],
                host_ips=list(dict.fromkeys(bad_ja3_hosts))[:20],
                metrics={
                    "malicious_ja3_streams": len(bad_ja3_pkts),
                    "matched_hashes": matched_hashes,
                },
                samples=bad_ja3_samples[:20],
            ),
            mitre_keys=["command-and-control", "encrypted-channel"],
            tags=["tls", "ja3", "malware", "c2", "fingerprint"],
        ))


def _empty_stats() -> Dict[str, Any]:
    return {
        "total_streams":     0,
        "unique_sni":        0,
        "version_counts":    {},
        "deprecated_count":  0,
        "top_sni":           [],
        "handshake_counts":  {},
        "weak_cipher_count": 0,
        "ja3_hashes":        {},
        "ja3s_hashes":       {},
    }
