import subprocess
import shutil
import json
import re


def sslyze_scan(target: str) -> dict:
    """
    Run SSLyze to analyze SSL/TLS configuration of a target.
    Checks supported protocols, cipher suites, certificate validity,
    and known vulnerabilities (Heartbleed, ROBOT, CCS injection, etc.).
    Uses --json_out for structured output.
    """
    sslyze_bin = shutil.which("sslyze")
    if not sslyze_bin:
        return {"skipped": True, "reason": "sslyze not installed"}

    host = target.strip()
    for prefix in ["http://", "https://", "ftp://"]:
        if host.startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0]
    # Keep port if specified, default to 443
    if ":" not in host:
        host_port = host + ":443"
    else:
        host_port = host
        host = host.split(":")[0]

    result = {
        "target": host_port,
        "certificate": {},
        "protocols": {},
        "cipher_suites": [],
        "total_accepted_ciphers": 0,
        "weak_ciphers": [],
        "total_weak_ciphers": 0,
        "vulnerabilities_tested": {},
        "vulnerabilities": [],
        "total_vulnerabilities": 0,
    }

    # Try JSON output first
    json_result = _run_sslyze_json(sslyze_bin, host_port)
    if json_result:
        _parse_json_result(json_result, result)
    else:
        # Fallback to text parsing
        text_output = _run_sslyze_text(sslyze_bin, host_port)
        if text_output:
            _parse_text_output(text_output, result)
        else:
            return {"skipped": True, "reason": "SSL/TLS connection failed or no response"}

    _detect_vulnerabilities(result)
    return result


def _run_sslyze_json(sslyze_bin: str, host_port: str) -> dict:
    """Run sslyze with JSON output."""
    try:
        cmd = [sslyze_bin, "--json_out=-", host_port]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                pass
    except (subprocess.TimeoutExpired, Exception):
        pass
    return None


def _run_sslyze_text(sslyze_bin: str, host_port: str) -> str:
    """Run sslyze with text output as fallback."""
    try:
        cmd = [sslyze_bin, "--regular", host_port]
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        return proc.stdout + "\n" + proc.stderr
    except (subprocess.TimeoutExpired, Exception):
        return None


def _parse_json_result(data: dict, result: dict):
    """Parse SSLyze JSON output."""
    servers = data.get("server_scan_results") or data.get("server_results") or []
    if not servers:
        return

    server = servers[0] if isinstance(servers, list) else servers
    scan_result = server.get("scan_result") or server.get("scan_commands_results") or {}

    # Certificate info
    cert_info = scan_result.get("certificate_info") or scan_result.get("certinfo") or {}
    _extract_certificate(cert_info, result)

    # Protocols
    protocol_map = {
        "ssl_2_0_cipher_suites": "SSLv2",
        "ssl_3_0_cipher_suites": "SSLv3",
        "tls_1_0_cipher_suites": "TLSv1.0",
        "tls_1_1_cipher_suites": "TLSv1.1",
        "tls_1_2_cipher_suites": "TLSv1.2",
        "tls_1_3_cipher_suites": "TLSv1.3",
    }

    all_ciphers = []
    weak_ciphers = []
    protocols = {}

    for key, proto_name in protocol_map.items():
        proto_data = scan_result.get(key) or {}
        if isinstance(proto_data, dict):
            result_obj = proto_data.get("result") or proto_data
            accepted = result_obj.get("accepted_cipher_suites") or result_obj.get("accepted_ciphers") or []
            if accepted:
                protocols[proto_name] = {"supported": True, "cipher_count": len(accepted)}
                for c in accepted:
                    cipher_name = ""
                    if isinstance(c, dict):
                        cipher_suite = c.get("cipher_suite") or c
                        if isinstance(cipher_suite, dict):
                            cipher_name = cipher_suite.get("name") or cipher_suite.get("openssl_name", "")
                        else:
                            cipher_name = str(cipher_suite)
                    else:
                        cipher_name = str(c)

                    entry = {"name": cipher_name, "protocol": proto_name}
                    is_weak = _is_weak_cipher(cipher_name)
                    entry["weak"] = is_weak
                    all_ciphers.append(entry)
                    if is_weak:
                        weak_ciphers.append(entry)
            else:
                protocols[proto_name] = {"supported": False, "cipher_count": 0}

    result["protocols"] = protocols
    result["cipher_suites"] = all_ciphers
    result["total_accepted_ciphers"] = len(all_ciphers)
    result["weak_ciphers"] = weak_ciphers
    result["total_weak_ciphers"] = len(weak_ciphers)

    # Vulnerability tests
    vuln_tests = {}
    for test_name in ["heartbleed", "openssl_ccs_injection", "robot", "session_renegotiation"]:
        test_data = scan_result.get(test_name) or {}
        if isinstance(test_data, dict):
            test_result = test_data.get("result") or test_data
            is_vuln = test_result.get("is_vulnerable_to_heartbleed") or \
                      test_result.get("is_vulnerable_to_ccs_injection") or \
                      test_result.get("is_vulnerable_to_robot") or False
            vuln_tests[test_name] = {
                "tested": True,
                "vulnerable": bool(is_vuln),
            }
    result["vulnerabilities_tested"] = vuln_tests


def _extract_certificate(cert_info: dict, result: dict):
    """Extract certificate details."""
    cert = {}
    deployments = cert_info.get("result", cert_info).get("certificate_deployments") or \
                  cert_info.get("certificate_deployments") or []

    if deployments:
        dep = deployments[0] if isinstance(deployments, list) else deployments
        leaf = dep.get("received_certificate_chain") or []
        if leaf:
            leaf_cert = leaf[0] if isinstance(leaf, list) else leaf
            subj = leaf_cert.get("subject") if isinstance(leaf_cert, dict) else {}
            if isinstance(subj, dict):
                cert["subject"] = subj.get("rfc4514_string") or str(subj)
            issuer = leaf_cert.get("issuer") if isinstance(leaf_cert, dict) else {}
            if isinstance(issuer, dict):
                cert["issuer"] = issuer.get("rfc4514_string") or str(issuer)
            cert["not_before"] = leaf_cert.get("not_valid_before") if isinstance(leaf_cert, dict) else None
            cert["not_after"] = leaf_cert.get("not_valid_after") if isinstance(leaf_cert, dict) else None
            cert["serial"] = leaf_cert.get("serial_number") if isinstance(leaf_cert, dict) else None
            pk = leaf_cert.get("public_key") if isinstance(leaf_cert, dict) else {}
            if isinstance(pk, dict):
                cert["key_type"] = pk.get("algorithm")
                cert["key_size"] = pk.get("key_size")
            san = leaf_cert.get("subject_alternative_name") if isinstance(leaf_cert, dict) else {}
            if isinstance(san, dict):
                dns_names = san.get("dns") or []
                cert["san"] = dns_names[:20]

        trust = dep.get("leaf_certificate_subject_matches_hostname")
        cert["hostname_match"] = trust
        path_valid = dep.get("verified_certificate_chain")
        cert["chain_valid"] = path_valid is not None and len(path_valid) > 0 if isinstance(path_valid, list) else bool(path_valid)

    result["certificate"] = cert


def _parse_text_output(output: str, result: dict):
    """Fallback: parse sslyze text output."""
    protocols = {}
    ciphers = []
    weak = []
    current_proto = None

    for line in output.splitlines():
        stripped = line.strip()

        # Protocol headers
        for proto in ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"]:
            if proto in stripped and ("Cipher Suites" in stripped or "cipher suites" in stripped.lower()):
                current_proto = proto.replace("SSL ", "SSLv").replace("TLS ", "TLSv")
                protocols[current_proto] = {"supported": False, "cipher_count": 0}
                break

        # Accepted ciphers
        if current_proto and ("Accepted" in stripped or "accepted" in stripped.lower()):
            protocols[current_proto]["supported"] = True

        # Cipher suite lines
        cipher_match = re.match(r"^\s+(TLS_\S+|SSL_\S+|\S+_WITH_\S+)", stripped)
        if cipher_match and current_proto:
            name = cipher_match.group(1)
            protocols[current_proto]["cipher_count"] = protocols.get(current_proto, {}).get("cipher_count", 0) + 1
            protocols[current_proto]["supported"] = True
            entry = {"name": name, "protocol": current_proto}
            is_w = _is_weak_cipher(name)
            entry["weak"] = is_w
            ciphers.append(entry)
            if is_w:
                weak.append(entry)

        # Certificate info
        if "Subject:" in stripped:
            result["certificate"]["subject"] = stripped.split("Subject:", 1)[1].strip()
        elif "Issuer:" in stripped:
            result["certificate"]["issuer"] = stripped.split("Issuer:", 1)[1].strip()
        elif "Not Before:" in stripped:
            result["certificate"]["not_before"] = stripped.split("Not Before:", 1)[1].strip()
        elif "Not After:" in stripped:
            result["certificate"]["not_after"] = stripped.split("Not After:", 1)[1].strip()

        # Heartbleed
        if "heartbleed" in stripped.lower():
            is_vuln = "vulnerable" in stripped.lower() and "not vulnerable" not in stripped.lower()
            result["vulnerabilities_tested"]["heartbleed"] = {"tested": True, "vulnerable": is_vuln}

        # ROBOT
        if "robot" in stripped.lower():
            is_vuln = "vulnerable" in stripped.lower() and "not vulnerable" not in stripped.lower()
            result["vulnerabilities_tested"]["robot"] = {"tested": True, "vulnerable": is_vuln}

    result["protocols"] = protocols
    result["cipher_suites"] = ciphers
    result["total_accepted_ciphers"] = len(ciphers)
    result["weak_ciphers"] = weak
    result["total_weak_ciphers"] = len(weak)


def _is_weak_cipher(name: str) -> bool:
    """Check if a cipher suite is considered weak."""
    name_upper = name.upper()
    weak_patterns = [
        "RC4", "DES", "3DES", "NULL", "EXPORT", "anon",
        "MD5", "RC2", "IDEA", "SEED", "CAMELLIA",
        "CBC3", "DES_CBC", "_DES_",
    ]
    return any(p.upper() in name_upper for p in weak_patterns)


def _detect_vulnerabilities(result: dict):
    """Detect SSL/TLS vulnerabilities."""
    vulns = []
    protocols = result.get("protocols", {})

    # SSLv2
    if protocols.get("SSLv2", {}).get("supported"):
        vulns.append({
            "title": "SSLv2 Enabled",
            "severity": "critical",
            "description": "SSLv2 is enabled. This protocol has fundamental design flaws and "
                           "is trivially breakable (DROWN attack).",
            "mitre": "T1557",
            "remediation": "Disable SSLv2 immediately. Use TLS 1.2 or TLS 1.3 only.",
        })

    # SSLv3
    if protocols.get("SSLv3", {}).get("supported"):
        vulns.append({
            "title": "SSLv3 Enabled (POODLE)",
            "severity": "high",
            "description": "SSLv3 is enabled. Vulnerable to POODLE attack (CVE-2014-3566) "
                           "allowing decryption of encrypted traffic.",
            "mitre": "T1557",
            "remediation": "Disable SSLv3. Use TLS 1.2 or TLS 1.3 only.",
        })

    # TLS 1.0
    if protocols.get("TLSv1.0", {}).get("supported"):
        vulns.append({
            "title": "TLS 1.0 Enabled (Deprecated)",
            "severity": "medium",
            "description": "TLS 1.0 is enabled. Deprecated since March 2021 (RFC 8996). "
                           "Vulnerable to BEAST attack and lacks modern cipher suites.",
            "mitre": "T1557",
            "remediation": "Disable TLS 1.0. Configure minimum TLS 1.2.",
        })

    # TLS 1.1
    if protocols.get("TLSv1.1", {}).get("supported"):
        vulns.append({
            "title": "TLS 1.1 Enabled (Deprecated)",
            "severity": "medium",
            "description": "TLS 1.1 is enabled. Deprecated since March 2021 (RFC 8996).",
            "mitre": "T1557",
            "remediation": "Disable TLS 1.1. Configure minimum TLS 1.2.",
        })

    # No TLS 1.3
    if not protocols.get("TLSv1.3", {}).get("supported") and protocols.get("TLSv1.2", {}).get("supported"):
        vulns.append({
            "title": "TLS 1.3 Not Supported",
            "severity": "low",
            "description": "TLS 1.3 is not enabled. TLS 1.3 provides improved security and performance "
                           "with 0-RTT handshake and no legacy cipher suites.",
            "mitre": "T1600.001",
            "remediation": "Enable TLS 1.3 support alongside TLS 1.2.",
        })

    # Weak ciphers
    weak = result.get("weak_ciphers", [])
    if weak:
        names = list(set(c["name"] for c in weak[:5]))
        vulns.append({
            "title": f"Weak Cipher Suites ({len(weak)})",
            "severity": "high",
            "description": f"{len(weak)} weak cipher suites accepted: {', '.join(names)}"
                           + ("..." if len(weak) > 5 else "")
                           + ". These include RC4, DES, 3DES, NULL, EXPORT, or MD5-based ciphers.",
            "mitre": "T1600.001",
            "remediation": "Disable all weak ciphers. Use only AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
        })

    # Heartbleed
    hb = result.get("vulnerabilities_tested", {}).get("heartbleed", {})
    if hb.get("vulnerable"):
        vulns.append({
            "title": "Heartbleed Vulnerability (CVE-2014-0160)",
            "severity": "critical",
            "description": "Server is vulnerable to Heartbleed. Attackers can read server memory "
                           "including private keys, session tokens, and passwords.",
            "mitre": "T1190",
            "remediation": "Update OpenSSL immediately. Revoke and reissue all certificates. "
                           "Rotate all passwords and session tokens.",
        })

    # ROBOT
    robot = result.get("vulnerabilities_tested", {}).get("robot", {})
    if robot.get("vulnerable"):
        vulns.append({
            "title": "ROBOT Attack Vulnerability",
            "severity": "high",
            "description": "Server is vulnerable to ROBOT (Return Of Bleichenbacher's Oracle Threat). "
                           "RSA key exchange can be broken to decrypt TLS traffic.",
            "mitre": "T1557",
            "remediation": "Disable RSA key exchange. Use only ECDHE or DHE key exchange.",
        })

    # CCS Injection
    ccs = result.get("vulnerabilities_tested", {}).get("openssl_ccs_injection", {})
    if ccs.get("vulnerable"):
        vulns.append({
            "title": "OpenSSL CCS Injection (CVE-2014-0224)",
            "severity": "high",
            "description": "Server is vulnerable to CCS injection allowing man-in-the-middle attacks.",
            "mitre": "T1557",
            "remediation": "Update OpenSSL to a patched version.",
        })

    # Certificate issues
    cert = result.get("certificate", {})
    if cert.get("hostname_match") is False:
        vulns.append({
            "title": "Certificate Hostname Mismatch",
            "severity": "high",
            "description": "The server certificate does not match the hostname. "
                           "This may allow MITM attacks.",
            "mitre": "T1557",
            "remediation": "Obtain a certificate that includes the correct hostname in CN or SAN.",
        })

    if cert.get("key_size") and isinstance(cert["key_size"], int) and cert["key_size"] < 2048:
        vulns.append({
            "title": f"Weak Certificate Key ({cert['key_size']}-bit)",
            "severity": "high",
            "description": f"Certificate uses a {cert['key_size']}-bit key. "
                           f"Keys shorter than 2048 bits are considered weak.",
            "mitre": "T1600.001",
            "remediation": "Reissue certificate with minimum 2048-bit RSA or 256-bit ECDSA key.",
        })

    result["vulnerabilities"] = vulns
    result["total_vulnerabilities"] = len(vulns)
    result["critical_count"] = sum(1 for v in vulns if v["severity"] == "critical")
    result["high_count"] = sum(1 for v in vulns if v["severity"] == "high")
    result["medium_count"] = sum(1 for v in vulns if v["severity"] == "medium")
    result["low_count"] = sum(1 for v in vulns if v["severity"] == "low")
