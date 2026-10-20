import argparse
import ipaddress
import socket
import subprocess
import xml.etree.ElementTree as ET
import html
import json
import re
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path


# ---------- PROJECT PATHS ----------

BASE_DIR = Path.home() / "ReconGuard"
REPORT_DIR = BASE_DIR / "reports"
HISTORY_FILE = BASE_DIR / "scan_history.json"

TIMEZONE = ZoneInfo("Asia/Kolkata")


# ---------- TIME ----------

def current_time():
    return datetime.now(TIMEZONE)


# ---------- TARGET VALIDATION ----------

def validate_target(target):
    """Accept a bare IPv4 address or hostname/domain, not a full URL."""
    if (
        not isinstance(target, str)
        or not target
        or target.startswith("-")
        or any(char in target for char in "/\\@?#")
        or "://" in target
    ):
        return False

    try:
        ip = ipaddress.ip_address(target)
        return ip.version == 4 and is_allowed_scan_ip(str(ip))
    except ValueError:
        pass

    # Validate hostname labels before DNS lookup. URLs, ports, and IPv6 are not accepted.
    if len(target) > 253 or target.endswith("."):
        target = target[:-1] if target.endswith(".") else target
    labels = target.split(".")
    if not labels or any(
        not label or len(label) > 63
        or label.startswith("-") or label.endswith("-")
        or not all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in label)
        for label in labels
    ):
        return False

    try:
        socket.getaddrinfo(
            target, None, socket.AF_INET, socket.SOCK_STREAM
        )
        return True
    except (socket.gaierror, OSError):
        return False


def is_allowed_scan_ip(address):
    """Permit IPv4 loopback, private lab addresses, and public IPv4 targets."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False

    if ip.version != 4:
        return False

    # Reject special-purpose ranges regardless of whether Python classifies
    # them as private or global. Keep loopback for local testing.
    if ip.is_loopback:
        return True
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return False

    return ip.is_private or ip.is_global


# ---------- DNS INFORMATION ----------

def get_dns_info(target):
    info = {
        "target": target,
        "addresses": [],
        "reverse_hostname": None,
        "lookup_type": "",
    }

    try:
        ip = ipaddress.ip_address(target)
        info["lookup_type"] = "IP address / reverse DNS"
        info["addresses"] = [str(ip)]

        try:
            hostname, _, _ = socket.gethostbyaddr(str(ip))
            info["reverse_hostname"] = hostname
        except (socket.herror, socket.gaierror, OSError):
            pass

    except ValueError:
        info["lookup_type"] = "Forward DNS"

        try:
            results = socket.getaddrinfo(
                target, None, socket.AF_INET, socket.SOCK_STREAM
            )
            info["addresses"] = sorted({
                result[4][0] for result in results
            })
        except (socket.gaierror, OSError):
            pass

    return info


# ---------- TARGET SELECTION ----------

def choose_scan_ip(dns_info):
    candidates = [
        address for address in dns_info["addresses"]
        if is_allowed_scan_ip(address)
    ]

    if not candidates:
        print("\n[-] No permitted IPv4 address found for this target.")
        print("[i] IPv6 and special-purpose addresses are not supported.")
        return None

    if len(candidates) == 1:
        ip = ipaddress.ip_address(candidates[0])
        target_type = "public target" if ip.is_global else "lab target"
        print(f"\n[+] Selected {target_type}: {candidates[0]}")
        return candidates[0]

    print("\nResolved IPv4 addresses:")

    for index, address in enumerate(candidates, start=1):
        print(f"{index}. {address}")

    choice = input("Choose the IP to scan: ").strip()

    try:
        index = int(choice)
        if 1 <= index <= len(candidates):
            return candidates[index - 1]
    except ValueError:
        pass

    print("[-] Invalid selection.")
    return None


# ---------- PORT SELECTION ----------

def choose_ports():
    while True:
        print("\n========== NMAP SCAN OPTIONS ==========")
        print("1. Common ports (Nmap fast scan)")
        print("2. Ports 1-1000")
        print("3. All TCP ports (1-65535)")
        print("4. Custom ports or ranges")
        print("5. Back to main menu")

        choice = input("\nChoose an option: ").strip()

        if choice == "1":
            return "-F", "Common ports"

        if choice == "2":
            return "1-1000", "Ports 1-1000"

        if choice == "3":
            print("\n[!] A full TCP scan may take several minutes.")
            confirm = input(
                "Type YES to confirm the full scan: "
            ).strip()

            if confirm == "YES":
                return "-", "Full TCP scan"

            print("[-] Scan cancelled.")

        elif choice == "4":
            value = input(
                "Enter ports/ranges, e.g. 22,80,8000-8100: "
            ).strip()

            try:
                ports = set()

                for part in value.split(","):
                    part = part.strip()

                    if not part:
                        raise ValueError

                    if "-" in part:
                        pieces = part.split("-")
                        if len(pieces) != 2:
                            raise ValueError

                        start, end = map(int, pieces)

                        if not (1 <= start <= end <= 65535):
                            raise ValueError

                        ports.update(range(start, end + 1))

                    else:
                        port = int(part)
                        if not 1 <= port <= 65535:
                            raise ValueError
                        ports.add(port)

                if not ports:
                    raise ValueError

                return ",".join(map(str, sorted(ports))), "Custom ports"

            except ValueError:
                print("[-] Invalid port list or range.")

        elif choice == "5":
            return None, None

        elif choice != "3":
            print("[-] Invalid choice.")


# ---------- PORT COVERAGE HELPERS ----------

def parse_port_ranges(port_ranges):
    """Expand an Nmap comma-separated port/range string into a set of ports."""
    ports = set()
    if not isinstance(port_ranges, str) or not port_ranges.strip():
        return ports
    try:
        for part in port_ranges.split(","):
            part = part.strip()
            if not part:
                return set()
            if "-" in part:
                pieces = part.split("-")
                if len(pieces) != 2:
                    return set()
                start, end = map(int, pieces)
                if not (1 <= start <= end <= 65535):
                    return set()
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if not 1 <= port <= 65535:
                    return set()
                ports.add(port)
    except ValueError:
        return set()
    return ports


def port_selection_metadata(port_option, scan_name, parsed, detect_versions):
    """Describe requested and actual coverage; mark it unknown if XML is inconsistent."""
    requested = "top-100" if port_option == "-F" else (
        "all-tcp" if port_option == "-" else port_option
    )
    actual_ranges = parsed.get("port_ranges", "")
    actual_ports = parse_port_ranges(actual_ranges)
    coverage_known = (
        parsed.get("host_state") == "up"
        and bool(actual_ports)
        and len(actual_ports) == parsed.get("ports_checked")
    )
    return {
        "scan_mode": scan_name,
        "requested_ports": requested,
        "ports_checked": parsed.get("ports_checked", 0),
        "ports_scanned_ranges": actual_ranges,
        "coverage_known": coverage_known,
        "nmap_flags": parsed.get("nmap_flags", []),
        "version_detection": bool(detect_versions),
    }


def compare_scan_records(old_scan, new_scan):
    """Compare only ports known to have been covered by both scans."""
    old_coverage = old_scan.get("coverage", {})
    new_coverage = new_scan.get("coverage", {})
    old_known = bool(old_coverage.get("coverage_known"))
    new_known = bool(new_coverage.get("coverage_known"))

    result = {
        "coverage_comparable": old_known and new_known,
        "coverage_warning": None,
        "common_coverage_count": 0,
        "newly_open": [],
        "no_longer_open": [],
        "service_changes": [],
    }
    if not old_known or not new_known:
        result["coverage_warning"] = (
            "One or both scans lack reliable coverage metadata. "
            "Open-port additions/removals cannot be concluded safely."
        )
        return result

    old_coverage_ports = parse_port_ranges(old_coverage.get("ports_scanned_ranges", ""))
    new_coverage_ports = parse_port_ranges(new_coverage.get("ports_scanned_ranges", ""))
    common_coverage = old_coverage_ports & new_coverage_ports
    result["common_coverage_count"] = len(common_coverage)
    if old_coverage_ports != new_coverage_ports:
        result["coverage_warning"] = (
            "The scans used different port coverage. Changes are reported only "
            "for ports included in both scans."
        )

    def open_map(record):
        return {
            (item.get("protocol", "tcp"), item.get("port")): item
            for item in record.get("results", [])
            if item.get("status") == "OPEN"
            and item.get("protocol", "tcp") == "tcp"
            and item.get("port") in common_coverage
        }

    old_ports = open_map(old_scan)
    new_ports = open_map(new_scan)
    result["newly_open"] = [new_ports[key] for key in sorted(set(new_ports) - set(old_ports))]
    result["no_longer_open"] = [old_ports[key] for key in sorted(set(old_ports) - set(new_ports))]
    for key in sorted(set(old_ports) & set(new_ports)):
        old = old_ports[key]
        new = new_ports[key]
        old_details = (old.get("service", "Unknown"), old.get("product", ""), old.get("version", ""))
        new_details = (new.get("service", "Unknown"), new.get("product", ""), new.get("version", ""))
        if old_details != new_details:
            result["service_changes"].append({"port": key[1], "protocol": key[0], "before": old_details, "after": new_details})
    return result


# ---------- NMAP XML PARSER ----------

def parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)

    results = []
    aggregate_counts = {
        "OPEN": 0,
        "CLOSED": 0,
        "FILTERED/UNKNOWN": 0,
    }

    host = root.find("host")
    if host is None:
        raise ValueError("Nmap did not return host information.")

    status_node = host.find("status")
    host_state = (
        status_node.get("state", "unknown")
        if status_node is not None else "unknown"
    )

    for port_node in host.findall("./ports/port"):
        port_id = int(port_node.get("portid", "0"))
        protocol = port_node.get("protocol", "tcp")

        state_node = port_node.find("state")
        state = (
            state_node.get("state", "unknown")
            if state_node is not None else "unknown"
        )

        service_node = port_node.find("service")
        service = "Unknown"
        product = ""
        version = ""

        if service_node is not None:
            service = service_node.get("name", "Unknown")
            product = service_node.get("product", "")
            version = service_node.get("version", "")

        if state == "open":
            normalized = "OPEN"
        elif state == "closed":
            normalized = "CLOSED"
        else:
            normalized = "FILTERED/UNKNOWN"

        aggregate_counts[normalized] += 1

        results.append({
            "port": port_id,
            "protocol": protocol,
            "service": service,
            "product": product,
            "version": version,
            "status": normalized,
        })

    # Nmap groups many ports into extraports instead of
    # returning one XML entry for each port.
    extra_counts = {
        "open": "OPEN",
        "closed": "CLOSED",
        "filtered": "FILTERED/UNKNOWN",
        "open|filtered": "FILTERED/UNKNOWN",
        "closed|filtered": "FILTERED/UNKNOWN",
    }

    for extra in host.findall("./ports/extraports"):
        state = extra.get("state", "unknown")
        normalized = extra_counts.get(state, "FILTERED/UNKNOWN")

        try:
            count = int(extra.get("count", "0"))
        except ValueError:
            count = 0

        aggregate_counts[normalized] += count

    scaninfo = root.find("scaninfo")
    port_ranges = ""
    if scaninfo is not None:
        try:
            ports_checked = int(scaninfo.get("numservices", "0"))
        except ValueError:
            ports_checked = len(results)
        port_ranges = scaninfo.get("ports", "")
    else:
        ports_checked = sum(aggregate_counts.values())

    return {
        "host_state": host_state,
        "results": sorted(results, key=lambda item: item["port"]),
        "counts": aggregate_counts,
        "ports_checked": ports_checked,
        "port_ranges": port_ranges,
    }


# ---------- RUN NMAP ----------

def run_nmap(scan_ip, port_option, detect_versions):
    command = [
        "nmap",
        "-sT",
        "-Pn",
        "-n",
        "-T3",
        "--reason",
    ]

    if port_option == "-F":
        command.append("-F")
    else:
        command.extend(["-p", port_option])

    if detect_versions:
        command.extend(["-sV", "--version-light"])

    # XML is written to stdout; no temporary XML file is needed.

    command.extend(["-oX", "-", "--", scan_ip])
    print("\n[+] Running Nmap...")
    print("[i] Target:", scan_ip)
    print("[i] Port selection:", "fast scan" if port_option == "-F"
          else port_option)
    print("[i] Service detection:", "enabled" if detect_versions
          else "disabled")

    started = time.perf_counter()

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=1800,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print("[-] Nmap timed out after 30 minutes.")
        return None, None
    except FileNotFoundError:
        print("[-] Nmap is not installed or is not in PATH.")
        return None, None
    except OSError as exc:
        print(f"[-] Could not run Nmap: {exc}")
        return None, None

    duration = time.perf_counter() - started

    if completed.returncode != 0:
        print("[-] Nmap returned an error.")
        if completed.stderr:
            print(completed.stderr.strip()[:1500])
        return None, None

    try:
        parsed = parse_nmap_xml(completed.stdout)
    except (ET.ParseError, ValueError) as exc:
        print(f"[-] Could not parse Nmap XML: {exc}")
        if completed.stderr:
            print(completed.stderr.strip()[:1000])
        return None, None

    parsed["nmap_flags"] = command[1:command.index("-oX")]
    return parsed, duration


# ---------- SCAN HISTORY ----------

def load_history():
    if not HISTORY_FILE.exists():
        return []

    try:
        data = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        print("[-] Could not read scan history.")
        return []


def save_scan_history(record):
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    history = load_history()
    history.append(record)

    HISTORY_FILE.write_text(
        json.dumps(history, indent=2),
        encoding="utf-8",
    )

    print(f"[+] Scan history saved: {HISTORY_FILE}")


def compare_scans():
    history = load_history()
    if len(history) < 2:
        print("[-] At least two saved scans are required.")
        return

    print("\n========== COMPARE SCANS ==========")
    for index, record in enumerate(history, start=1):
        print(
            f"{index}. {record.get('target', 'Unknown')} | "
            f"{record.get('timestamp', 'Unknown')} | "
            f"{record.get('scan_mode', 'Older scan')}"
        )

    try:
        first = int(input("\nEnter the older scan number: "))
        second = int(input("Enter the newer scan number: "))
        if not (1 <= first <= len(history) and 1 <= second <= len(history)):
            print("[-] Invalid scan number.")
            return
        if first == second:
            print("[-] Choose two different scans.")
            return
    except ValueError:
        print("[-] Enter valid scan numbers.")
        return

    old_scan, new_scan = history[first - 1], history[second - 1]
    old_ip = old_scan.get("scan_ip") or old_scan.get("target")
    new_ip = new_scan.get("scan_ip") or new_scan.get("target")
    if old_ip != new_ip:
        print("[-] These scans have different target IPs/identifiers.")
        print("[i] Compare scans of the same target.")
        return

    comparison = compare_scan_records(old_scan, new_scan)
    print("\n========== COMPARISON RESULTS ==========")
    print(f"Target: {new_ip}")
    print(f"Older scan: {old_scan.get('timestamp', 'Unknown')}")
    print(f"Newer scan: {new_scan.get('timestamp', 'Unknown')}")

    if comparison["coverage_warning"]:
        print("\n[!] Coverage warning: " + comparison["coverage_warning"])

    if not comparison["coverage_comparable"]:
        print("\nNo open-port additions/removals reported because coverage is unknown.")
        print("[i] Clear legacy test history after testing, then use new-format scans.")
        return

    print(f"\nPorts covered by both scans: {comparison['common_coverage_count']}")
    print("\nNewly open ports:")
    if comparison["newly_open"]:
        for item in comparison["newly_open"]:
            print(f"  + {item.get('port')}/{item.get('protocol', 'tcp')} {item.get('service', 'Unknown')}")
    else:
        print("  None detected.")

    print("\nPorts no longer open:")
    if comparison["no_longer_open"]:
        for item in comparison["no_longer_open"]:
            print(f"  - {item.get('port')}/{item.get('protocol', 'tcp')} {item.get('service', 'Unknown')}")
    else:
        print("  None detected.")

    print("\nService/version changes:")
    if comparison["service_changes"]:
        for change in comparison["service_changes"]:
            print(f"  * {change['port']}/{change['protocol']}")
            print(f"      Before: {' '.join(change['before'])}")
            print(f"      After:  {' '.join(change['after'])}")
    else:
        print("  None detected.")


def view_history():
    history = load_history()

    print("\n========== SCAN HISTORY ==========")

    if not history:
        print("No scans saved yet.")
        return

    for index, record in enumerate(history, start=1):
        summary = record.get("summary", {})
        print(f"\nScan #{index}")
        print(f"Target:     {record.get('target', 'Unknown')}")
        print(f"Scan IP:    {record.get('scan_ip', 'Not recorded')}")
        print(f"Time:       {record.get('timestamp', 'Unknown')}")
        print(f"Scan type:  {record.get('scan_mode', 'Older scan')}")
        print(f"Ports checked: {summary.get('ports_checked', 'Unknown')}")
        print(f"Open ports: {summary.get('OPEN', 'Unknown')}")
        coverage = record.get("coverage", {})
        if coverage:
            print(f"Coverage:   {coverage.get('ports_scanned_ranges') or 'Unknown'}")
            print(f"Nmap flags: {' '.join(coverage.get('nmap_flags', [])) or 'Unknown'}")

        for item in record.get("results", []):
            if item.get("status") == "OPEN":
                service = item.get("service", "Unknown")
                print(f"  - {item.get('port')}/tcp {service}")

        print("-" * 40)


# ---------- HTML REPORT ----------

def generate_report(
    target, scan_ip, dns_info, parsed, scan_name,
    started_at, generated_at, duration, version_detection
):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    counts = parsed["counts"]
    results = parsed["results"]

    open_rows = []
    for item in results:
        if item["status"] != "OPEN":
            continue

        service_info = " ".join(
            part for part in (item["product"], item["version"]) if part
        )
        service = item["service"]
        if service_info:
            service += " — " + service_info

        open_rows.append(
            "<tr>"
            f"<td>{item['port']}/{html.escape(item['protocol'])}</td>"
            f"<td>{html.escape(service)}</td>"
            f"<td>{html.escape(item['status'])}</td>"
            "</tr>"
        )

    addresses = "".join(
        f"<li>{html.escape(address)}</li>"
        for address in dns_info["addresses"]
    )

    hostname = (
        html.escape(dns_info["reverse_hostname"])
        if dns_info["reverse_hostname"] else "Not available"
    )

    report_name = (
        "report_" + generated_at.strftime("%Y%m%d_%H%M%S_%f") + ".html"
    )
    report_file = REPORT_DIR / report_name

    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ReconGuard Security Report</title>
<style>
body {{ font-family: Arial, sans-serif; max-width: 1000px;
       margin: 35px auto; padding: 0 18px; color: #222;
       background: #f4f6f8; }}
h1 {{ color: #17365d; }}
.card {{ background: white; padding: 20px;
         margin: 18px 0; border-radius: 8px; overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; }}
th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #e9eef5; }}
</style>
</head>
<body>
<h1>ReconGuard Security Report</h1>
<p>Scan started: {started_at.strftime('%Y-%m-%d %H:%M:%S %Z')}</p>
<p>Report generated: {generated_at.strftime('%Y-%m-%d %H:%M:%S %Z')}</p>

<div class="card">
<h2>Scan Details</h2>
<p><strong>Input target:</strong> {html.escape(target)}</p>
<p><strong>Scanned IP:</strong> {html.escape(scan_ip)}</p>
<p><strong>Scan type:</strong> {html.escape(scan_name)}</p>
<p><strong>Host state:</strong> {html.escape(parsed['host_state'])}</p>
<p><strong>Ports checked:</strong> {parsed['ports_checked']}</p>
<p><strong>Duration:</strong> {duration:.2f} seconds</p>
<p><strong>Service detection:</strong> {'Enabled' if version_detection else 'Disabled'}</p>
<p><strong>Ports scanned:</strong> {html.escape(parsed.get('port_ranges', 'Unknown') or 'Unknown')}</p>
<p><strong>Nmap flags:</strong> {html.escape(' '.join(parsed.get('nmap_flags', [])) or 'Unknown')}</p>
</div>

<div class="card">
<h2>DNS Information</h2>
<p><strong>Lookup type:</strong> {html.escape(dns_info['lookup_type'])}</p>
<ul>{addresses or '<li>No addresses returned</li>'}</ul>
<p><strong>Reverse hostname:</strong> {hostname}</p>
</div>

<div class="card">
<h2>Scan Summary</h2>
<p>Open: {counts['OPEN']}</p>
<p>Closed: {counts['CLOSED']}</p>
<p>Filtered/unknown: {counts['FILTERED/UNKNOWN']}</p>
</div>

<div class="card">
<h2>Open Ports</h2>
<table>
<thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead>
<tbody>{''.join(open_rows) or '<tr><td colspan="3">No open ports reported</td></tr>'}</tbody>
</table>
<p>Closed ports are summarized above rather than listed individually.</p>
</div>

<div class="card">
<h2>Limitations</h2>
<p>ReconGuard uses Nmap for TCP scanning. Service/version detection
is an estimate and may be inconclusive. This report does not prove
that a vulnerability exists. Timeouts, host filtering, and network
conditions can affect results. Scan only systems you own or have
permission to test.</p>
</div>
</body>
</html>
"""

    report_file.write_text(document, encoding="utf-8")
    print(f"[+] HTML report saved: {report_file}")


# ---------- RUN A SCAN ----------

def run_scan():
    target = input("Enter an IPv4 address or domain: ").strip()

    if not target:
        print("[-] Please enter a target.")
        return

    if not validate_target(target):
        print("[-] Invalid or unresolvable target.")
        return

    dns_info = get_dns_info(target)

    print("\n========== DNS INFORMATION ==========")
    print(f"Input target: {target}")
    print(f"Lookup type:  {dns_info['lookup_type']}")

    for address in dns_info["addresses"]:
        print(f"[+] Address: {address}")

    if dns_info["reverse_hostname"]:
        print(f"[+] Reverse hostname: {dns_info['reverse_hostname']}")

    scan_ip = choose_scan_ip(dns_info)
    if scan_ip is None:
        return

    parsed_ip = ipaddress.ip_address(scan_ip)
    is_public_target = parsed_ip.is_global

    print("\n[!] Only scan systems you own or have explicit permission to test.")
    confirmation = input(
        f"Confirm authorization to scan {scan_ip} (yes/no): "
    ).strip().lower()

    if confirmation != "yes":
        print("[-] Scan cancelled.")
        return

    if is_public_target:
        print("\n[!] Public target selected. ReconGuard will use a conservative common-port scan.")
        print("[!] Service/version detection and full/custom port scans are disabled for public targets.")
        public_confirmation = input(
            "Type SCAN PUBLIC to confirm this authorized public scan: "
        ).strip()
        if public_confirmation != "SCAN PUBLIC":
            print("[-] Public scan cancelled.")
            return
        port_option, scan_name = "-F", "Common ports (public target)"
        version_detection = False
    else:
        port_option, scan_name = choose_ports()
        if port_option is None:
            return

        version_choice = input(
            "Enable service/version detection? (y/n): "
        ).strip().lower()
        version_detection = version_choice == "y"

    started_at = current_time()

    parsed, duration = run_nmap(
        scan_ip, port_option, version_detection
    )

    if parsed is None:
        return

    generated_at = current_time()
    counts = parsed["counts"]

    print("\n========== NMAP SCAN SUMMARY ==========")
    print(f"Target:               {scan_ip}")
    print(f"Host state:           {parsed['host_state']}")
    print(f"Ports checked:        {parsed['ports_checked']}")
    print(f"Open ports:           {counts['OPEN']}")
    print(f"Closed ports:         {counts['CLOSED']}")
    print(f"Filtered/unknown:     {counts['FILTERED/UNKNOWN']}")
    print(f"Duration:             {duration:.2f} seconds")

    print("\nOpen ports:")
    open_results = [
        item for item in parsed["results"]
        if item["status"] == "OPEN"
    ]

    if open_results:
        for item in open_results:
            service_info = " ".join(
                part for part in (item["product"], item["version"]) if part
            )
            print(
                f"  {item['port']}/tcp  {item['service']}  "
                f"{service_info}".rstrip()
            )
    else:
        print("  No open ports reported.")

    record = {
        "target": target,
        "scan_ip": scan_ip,
        "timestamp": started_at.isoformat(),
        "report_generated_at": generated_at.isoformat(),
        "scan_mode": scan_name,
        "version_detection": version_detection,
        "coverage": port_selection_metadata(port_option, scan_name, parsed, version_detection),
        "duration_seconds": round(duration, 2),
        "summary": {
            "ports_checked": parsed["ports_checked"],
            **counts,
        },
        "dns": dns_info,
        "results": parsed["results"],
    }

    save_scan_history(record)

    report_choice = input(
        "\nGenerate an HTML report? (y/n): "
    ).strip().lower()

    if report_choice == "y":
        generate_report(
            target,
            scan_ip,
            dns_info,
            parsed,
            scan_name,
            started_at,
            generated_at,
            duration,
            version_detection,
        )
    else:
        print("[i] HTML report generation skipped.")

# ---------- CLI MODE ----------

def normalize_cli_ports(value):
    """Convert a CLI port selection into the Nmap option and display name."""
    value = value.strip().lower()
    if value == "common":
        return "-F", "Common ports"
    if value in {"1-1000", "all"}:
        if value == "all":
            return "-", "Full TCP scan"
        return "1-1000", "Ports 1-1000"
    ports = parse_port_ranges(value)
    if not ports:
        raise ValueError("Invalid ports. Use common, 1-1000, all, or e.g. 22,80,8000-8100.")
    # Reject malformed ranges by ensuring canonical parsed count matches input intent.
    return ",".join(map(str, sorted(ports))), "Custom ports"


def run_cli_scan(args):
    if not args.authorized:
        print("[-] CLI scans require --authorized to confirm you have permission.")
        return 2
    if not validate_target(args.target):
        print("[-] Invalid or unresolvable target.")
        return 2

    dns_info = get_dns_info(args.target)
    candidates = [ip for ip in dns_info["addresses"] if is_allowed_scan_ip(ip)]
    if args.scan_ip:
        if args.scan_ip not in candidates:
            print("[-] --scan-ip must be one of the target's resolved, permitted IPv4 addresses.")
            return 2
        scan_ip = args.scan_ip
    elif len(candidates) == 1:
        scan_ip = candidates[0]
    elif len(candidates) > 1:
        print("[-] Target resolves to multiple addresses. Specify one with --scan-ip.")
        return 2
    else:
        print("[-] No permitted IPv4 address found.")
        return 2

    is_public = ipaddress.ip_address(scan_ip).is_global
    try:
        port_option, scan_name = normalize_cli_ports(args.ports)
    except ValueError as exc:
        print(f"[-] {exc}")
        return 2

    if is_public:
        if not args.confirm_public:
            print("[-] Public targets require --confirm-public in addition to --authorized.")
            return 2
        if port_option != "-F":
            print("[-] Public targets are restricted to --ports common.")
            return 2
        if args.version_detection:
            print("[-] Service/version detection is disabled for public targets.")
            return 2
        scan_name = "Common ports (public target)"

    started_at = current_time()
    parsed, duration = run_nmap(scan_ip, port_option, args.version_detection)
    if parsed is None:
        return 1
    generated_at = current_time()
    counts = parsed["counts"]
    print("\n========== NMAP SCAN SUMMARY ==========")
    print(f"Target: {scan_ip}")
    print(f"Ports checked: {parsed['ports_checked']}")
    print(f"Open ports: {counts['OPEN']}")
    print(f"Closed ports: {counts['CLOSED']}")
    print(f"Filtered/unknown: {counts['FILTERED/UNKNOWN']}")
    record = {
        "target": args.target,
        "scan_ip": scan_ip,
        "timestamp": started_at.isoformat(),
        "report_generated_at": generated_at.isoformat(),
        "scan_mode": scan_name,
        "version_detection": args.version_detection,
        "coverage": port_selection_metadata(port_option, scan_name, parsed, args.version_detection),
        "duration_seconds": round(duration, 2),
        "summary": {"ports_checked": parsed["ports_checked"], **counts},
        "dns": dns_info,
        "results": parsed["results"],
    }
    save_scan_history(record)
    if args.report:
        generate_report(args.target, scan_ip, dns_info, parsed, scan_name, started_at,
                        generated_at, duration, args.version_detection)
    return 0


# ---------- MAIN MENU ----------

def main():
    parser = argparse.ArgumentParser(description="ReconGuard Nmap reconnaissance and reporting tool")
    parser.add_argument("--target", help="Run one scan against an IPv4 address or domain instead of opening the menu")
    parser.add_argument("--scan-ip", help="Explicit resolved IPv4 address when a domain has multiple addresses")
    parser.add_argument("--ports", default="common", help="common, 1-1000, all, or a custom list/range such as 22,80,8000-8100")
    parser.add_argument("--version-detection", action="store_true", help="Enable light service/version detection for private/loopback lab targets")
    parser.add_argument("--authorized", action="store_true", help="Confirm that you own the target or have explicit permission to scan it")
    parser.add_argument("--confirm-public", action="store_true", help="Explicitly confirm an authorized public-target scan; public scans are limited to common ports")
    parser.add_argument("--report", action="store_true", help="Generate an HTML report after a successful CLI scan")
    args = parser.parse_args()

    if args.target:
        return run_cli_scan(args)
    if any((args.scan_ip, args.version_detection, args.authorized, args.confirm_public, args.report)) or args.ports != "common":
        parser.error("CLI scan options such as --ports and --authorized require --target.")

    while True:
        print("\n" + "=" * 42)
        print("          ReconGuard v1.0")
        print("=" * 42)
        print("1. Run a new scan")
        print("2. View scan history")
        print("3. Compare two scans")
        print("4. Exit")
        choice = input("\nChoose an option: ").strip()
        if choice == "1":
            run_scan()
        elif choice == "2":
            view_history()
        elif choice == "3":
            compare_scans()
        elif choice == "4":
            print("Exiting ReconGuard. Goodbye!")
            break
        else:
            print("[-] Invalid choice. Enter 1, 2, 3 or 4.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
