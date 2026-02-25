import subprocess
import json
import re
import shutil


def _clean_target(target: str) -> str:
    """Strip protocol, path, port from target."""
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


def dnsx_scan(target: str, subdomains: list = None) -> dict:
    """Run dnsx DNS resolution and record enumeration.

    Resolves DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, PTR)
    for the target and optional subdomain list.

    Args:
        target: Domain name or hostname.
        subdomains: Optional list of subdomains to resolve.

    Returns:
        Dict with DNS resolution results.
    """
    host = _clean_target(target)
    if not host:
        return {"skipped": True, "reason": "empty target"}

    dnsx_bin = shutil.which("dnsx")
    if not dnsx_bin:
        return {"skipped": True, "reason": "dnsx not installed"}

    # Build input list
    hosts = set()
    hosts.add(host)
    if subdomains:
        for s in subdomains:
            s = s.strip().lower()
            if s:
                hosts.add(s)

    input_text = "\n".join(sorted(hosts))

    try:
        cmd = [
            dnsx_bin,
            "-silent",
            "-json",
            "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa", "-ptr",
            "-resp",
            "-retry", "2",
            "-rate-limit", "50",
            "-threads", "25",
        ]

        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=240,
        )

        results = []
        all_ips = set()
        all_cnames = set()
        all_mx = set()
        all_ns = set()
        all_txt = []
        record_types_found = set()
        resolved_hosts = set()
        unresolved_hosts = set()

        output = proc.stdout.strip()
        if output:
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)

                    rec_host = rec.get("host", rec.get("name", ""))
                    if not rec_host:
                        continue

                    entry = {"host": rec_host}
                    has_records = False

                    # A records
                    a_records = rec.get("a", [])
                    if a_records:
                        entry["a"] = a_records
                        for ip in a_records:
                            all_ips.add(ip)
                        record_types_found.add("A")
                        has_records = True

                    # AAAA records
                    aaaa_records = rec.get("aaaa", [])
                    if aaaa_records:
                        entry["aaaa"] = aaaa_records
                        for ip in aaaa_records:
                            all_ips.add(ip)
                        record_types_found.add("AAAA")
                        has_records = True

                    # CNAME records
                    cname_records = rec.get("cname", [])
                    if cname_records:
                        entry["cname"] = cname_records
                        for c in cname_records:
                            all_cnames.add(c)
                        record_types_found.add("CNAME")
                        has_records = True

                    # MX records
                    mx_records = rec.get("mx", [])
                    if mx_records:
                        entry["mx"] = mx_records
                        for m in mx_records:
                            all_mx.add(m)
                        record_types_found.add("MX")
                        has_records = True

                    # NS records
                    ns_records = rec.get("ns", [])
                    if ns_records:
                        entry["ns"] = ns_records
                        for n in ns_records:
                            all_ns.add(n)
                        record_types_found.add("NS")
                        has_records = True

                    # TXT records
                    txt_records = rec.get("txt", [])
                    if txt_records:
                        entry["txt"] = txt_records
                        all_txt.extend(txt_records)
                        record_types_found.add("TXT")
                        has_records = True

                    # SOA record
                    soa_records = rec.get("soa", [])
                    if soa_records:
                        entry["soa"] = soa_records
                        record_types_found.add("SOA")
                        has_records = True

                    # PTR records
                    ptr_records = rec.get("ptr", [])
                    if ptr_records:
                        entry["ptr"] = ptr_records
                        record_types_found.add("PTR")
                        has_records = True

                    # Status code
                    status = rec.get("status_code", "")
                    if status:
                        entry["status_code"] = status

                    if has_records:
                        results.append(entry)
                        resolved_hosts.add(rec_host)
                    else:
                        unresolved_hosts.add(rec_host)

                except json.JSONDecodeError:
                    continue

        # Sort results by host
        results.sort(key=lambda r: r.get("host", ""))

        # Detect security-relevant TXT records
        security_txt = []
        for txt in all_txt:
            txt_lower = txt.lower() if isinstance(txt, str) else ""
            if any(k in txt_lower for k in ["spf", "dkim", "dmarc", "v=spf", "v=dkim", "v=dmarc", "google-site-verification", "ms=", "docusign", "facebook-domain", "amazonses"]):
                security_txt.append(txt)

        # Detect potential subdomain takeover (CNAME to non-resolving)
        dangling_cnames = []
        for entry in results:
            cnames = entry.get("cname", [])
            a_recs = entry.get("a", [])
            if cnames and not a_recs:
                dangling_cnames.append({
                    "host": entry["host"],
                    "cname": cnames,
                })

        return {
            "target": host,
            "total_queried": len(hosts),
            "total_resolved": len(resolved_hosts),
            "total_unresolved": len(unresolved_hosts),
            "results": results,
            "all_ips": sorted(all_ips),
            "all_cnames": sorted(all_cnames),
            "all_mx": sorted(all_mx),
            "all_ns": sorted(all_ns),
            "security_txt": security_txt,
            "dangling_cnames": dangling_cnames,
            "record_types": sorted(record_types_found),
            "summary": {
                "queried": len(hosts),
                "resolved": len(resolved_hosts),
                "unresolved": len(unresolved_hosts),
                "unique_ips": len(all_ips),
                "cnames": len(all_cnames),
                "mx_servers": len(all_mx),
                "ns_servers": len(all_ns),
                "txt_records": len(all_txt),
                "security_txt": len(security_txt),
                "dangling_cnames": len(dangling_cnames),
                "record_types": len(record_types_found),
            },
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "dnsx timeout (240s)"}
    except FileNotFoundError:
        return {"skipped": True, "reason": "dnsx not installed"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
