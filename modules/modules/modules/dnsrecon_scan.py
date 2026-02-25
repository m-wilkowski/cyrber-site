import subprocess
import json
import os
import re
import tempfile
import shutil


def _clean_target(target: str) -> str:
    """Strip protocol, path, port from target."""
    host = re.sub(r'^https?://', '', target).split('/')[0].split(':')[0]
    return host.strip().lower()


def _parse_txt_records(records: list) -> dict:
    """Classify TXT records into SPF, DMARC, DKIM, and other."""
    spf = []
    dmarc = []
    dkim = []
    other = []

    for rec in records:
        val = rec.get("strings", "") or rec.get("string", "") or rec.get("data", "") or ""
        if isinstance(val, list):
            val = " ".join(val)
        val = str(val).strip()
        if not val:
            continue

        val_lower = val.lower()
        if val_lower.startswith("v=spf1"):
            spf.append(val)
        elif val_lower.startswith("v=dmarc1"):
            dmarc.append(val)
        elif "dkim" in val_lower or val_lower.startswith("v=dkim"):
            dkim.append(val)
        else:
            other.append(val)

    return {"spf": spf, "dmarc": dmarc, "dkim": dkim, "other": other}


def dnsrecon_scan(target: str) -> dict:
    """Run dnsrecon against target and parse results.

    Args:
        target: Domain name or hostname.

    Returns:
        Dict with DNS reconnaissance results.
    """
    host = _clean_target(target)
    if not host:
        return {"skipped": True, "reason": "empty target"}

    # Check if dnsrecon is available
    dnsrecon_bin = shutil.which("dnsrecon")
    if not dnsrecon_bin:
        # Try common locations
        for path in ["/usr/local/bin/dnsrecon", "/opt/dnsrecon/dnsrecon.py"]:
            if os.path.isfile(path):
                dnsrecon_bin = path
                break
    if not dnsrecon_bin:
        return {"skipped": True, "reason": "dnsrecon not installed"}

    # Temp file for JSON output
    json_out = os.path.join(tempfile.gettempdir(), f"dnsrecon_{host}.json")

    try:
        cmd = [
            dnsrecon_bin,
            "-d", host,
            "-t", "std,brt,srv,axfr",
            "-j", json_out,
        ]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Parse JSON output
        records = []
        if os.path.isfile(json_out):
            try:
                with open(json_out, "r") as f:
                    records = json.load(f)
                if not isinstance(records, list):
                    records = [records] if records else []
            except (json.JSONDecodeError, IOError):
                records = []
            finally:
                try:
                    os.remove(json_out)
                except OSError:
                    pass

        # Classify records
        a_records = []
        mx_records = []
        ns_records = []
        txt_raw = []
        srv_records = []
        subdomains = set()
        zone_transfer = False

        for rec in records:
            rtype = (rec.get("type") or "").upper()
            name = rec.get("name", "") or ""
            address = rec.get("address", "") or ""

            if rtype == "A" or rtype == "AAAA":
                a_records.append({
                    "hostname": name,
                    "ip": address,
                    "type": rtype,
                })
                # Track subdomains
                if name and name != host and name.endswith("." + host):
                    subdomains.add(name)

            elif rtype == "MX":
                exchange = rec.get("exchange", "") or rec.get("target", "") or address
                priority = rec.get("priority", 0)
                if exchange:
                    mx_records.append({
                        "exchange": exchange,
                        "priority": priority,
                    })

            elif rtype == "NS":
                ns_val = rec.get("target", "") or rec.get("ns_server", "") or address or name
                if ns_val:
                    ns_records.append(ns_val)

            elif rtype == "TXT":
                txt_raw.append(rec)

            elif rtype == "SRV":
                srv_target = rec.get("target", "") or address
                port = rec.get("port", 0)
                priority = rec.get("priority", 0)
                service = name
                if srv_target:
                    srv_records.append({
                        "service": service,
                        "target": srv_target,
                        "port": port,
                        "priority": priority,
                    })

            elif rtype == "AXFR" or rtype == "zone_transfer":
                zone_transfer = True

            # Collect subdomains from brute-force results
            if name and name != host and name.endswith("." + host):
                subdomains.add(name)

        # Check for zone transfer in stdout as well
        stdout = proc.stdout or ""
        if "zone transfer" in stdout.lower() and "successful" in stdout.lower():
            zone_transfer = True

        # Parse TXT records
        txt_classified = _parse_txt_records(txt_raw)
        spf_configured = len(txt_classified["spf"]) > 0
        dmarc_configured = len(txt_classified["dmarc"]) > 0

        # Build TXT records output
        txt_records = []
        for spf_val in txt_classified["spf"]:
            txt_records.append({"type": "SPF", "value": spf_val})
        for dmarc_val in txt_classified["dmarc"]:
            txt_records.append({"type": "DMARC", "value": dmarc_val})
        for dkim_val in txt_classified["dkim"]:
            txt_records.append({"type": "DKIM", "value": dkim_val})
        for other_val in txt_classified["other"]:
            txt_records.append({"type": "TXT", "value": other_val})

        # Deduplicate NS records
        ns_records = sorted(set(ns_records))

        # Sort MX by priority
        mx_records.sort(key=lambda x: x.get("priority", 0))

        return {
            "target": host,
            "a_records": a_records,
            "mx_records": mx_records,
            "ns_records": ns_records,
            "txt_records": txt_records,
            "srv_records": srv_records,
            "zone_transfer": zone_transfer,
            "subdomains": sorted(subdomains),
            "spf_configured": spf_configured,
            "dmarc_configured": dmarc_configured,
            "total_records": len(records),
        }

    except subprocess.TimeoutExpired:
        return {"skipped": True, "reason": "dnsrecon timeout (120s)"}
    except FileNotFoundError:
        return {"skipped": True, "reason": "dnsrecon not installed"}
    except Exception as e:
        return {"skipped": True, "reason": str(e)}
    finally:
        # Cleanup temp file
        try:
            if os.path.isfile(json_out):
                os.remove(json_out)
        except OSError:
            pass
