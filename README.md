# ReconGuard

**Python-Based Network Reconnaissance and Reporting Tool**

ReconGuard is a network reconnaissance tool that integrates Nmap with Python to scan TCP ports, record scan history, compare results, and generate HTML reports. It is designed for cybersecurity learning, authorized assessments, and controlled lab environments.

## Features

- **Nmap Integration:** Perform TCP port scans using Nmap.
- **Flexible Port Selection:** Scan common ports (Nmap's top 100 TCP ports), ports 1–1000, all TCP ports, or custom port lists and ranges.
- **Target Validation:** Accept IPv4 addresses and domain names, with support for selecting an IPv4 address when a domain resolves to multiple addresses.
- **Option-Like Target Rejection:** Reject targets beginning with `-` to prevent them from being interpreted as command-line options.
- **Optional Service Detection:** Enable light service/version detection for private or loopback lab targets. Version detection sends additional probes, making it more intrusive than a basic port scan.
- **JSON Scan History:** Store scan records for later review.
- **Scan Comparison:** Identify open-port and service changes within the ports covered by both scans.
- **Recorded Coverage Metadata:** Store port ranges, scan mode, Nmap flags, and service-detection settings to help interpret comparisons.
- **HTML Reporting:** Generate reports for completed scans.
- **Command-Line Interface:** Run scans using command-line arguments or the interactive menu.
- **Automated Testing:** Test input validation, Nmap XML parsing, coverage metadata, and scan-comparison behavior.

## Technologies

- Python 3
- Nmap
- JSON for scan history
- HTML for reports
- Python `unittest` for automated testing

## Requirements

- Tested on Linux (Kali)
- Python 3
- Nmap installed and available in your system PATH

The core application uses Python's standard library and does not require additional Python packages.

Check your installed versions with:

```bash
python3 --version
nmap --version
```

## Installation

### 1. Install Nmap

On Kali Linux:

```bash
sudo apt update
sudo apt install nmap
```

### 2. Clone the repository

Replace `YOUR_GITHUB_USERNAME` with your GitHub username after publishing the repository.

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/ReconGuard.git
cd ReconGuard
```

## Usage

The main application entry point is `reconguard.py`.

### Display command-line options

```bash
python3 reconguard.py --help
```

### Start the interactive menu

```bash
python3 reconguard.py
```

### Scan your local machine

```bash
python3 reconguard.py --target 127.0.0.1 --ports common --authorized --report
```

### Scan a private lab machine

Replace the example IP with the address of your own lab target.

```bash
python3 reconguard.py --target 192.168.56.101 --ports 1-1000 --authorized --report
```

### Scan selected ports

```bash
python3 reconguard.py --target 127.0.0.1 --ports 22,80,443 --authorized
```

### Enable light service/version detection

```bash
python3 reconguard.py --target 127.0.0.1 --ports common --version-detection --authorized --report
```

Service/version detection is intended for private or loopback lab targets because it sends additional probes.

### Public-target scanning

Public-target scans require both `--authorized` and `--confirm-public`.

- `--authorized` confirms that you claim to own the target or have explicit permission to scan it.
- `--confirm-public` explicitly confirms an authorized public-target scan.

These flags are **user confirmations, not independent verification of ownership or permission**. They do not establish authorization on their own.

Public-target scans are restricted by the application to common ports. Only scan systems you own or have explicit permission to test, and follow applicable laws and the target owner's rules.

## Example Output

The following output is based on a successful local scan of `127.0.0.1` using the command shown above:

```text
[+] Running Nmap...
[i] Target: 127.0.0.1
[i] Port selection: fast scan
[i] Service detection: disabled

========== NMAP SCAN SUMMARY ==========
Target: 127.0.0.1
Ports checked: 100
Open ports: 1
Closed ports: 99
Filtered/unknown: 0
[+] Scan history saved: scan_history.json
[+] HTML report saved: reports/<generated-report>.html
```

Actual results and generated report filenames vary depending on the target, running services, firewall configuration, and scan settings. This example does not imply that a particular port is open on every system.

A sample HTML report generated from a localhost scan is available at:

`examples/sample_report.html`

Before publishing the sample report, inspect it for sensitive IP addresses, hostnames, usernames, file paths, and other machine-specific information.

## Testing

Run the automated tests from the project directory:

```bash
python3 -m unittest discover -s tests -v
```

See the test suite for current coverage, including:

- Port-range parsing and input validation
- Rejection of invalid hosts, full URLs, and option-like targets
- Nmap XML parsing and invalid XML
- Recording scan-coverage metadata
- Comparisons across different port ranges
- Changes within shared scan coverage
- Handling unknown coverage metadata

The project also requires practical end-to-end checks of the CLI, local scanning, scan-history saving, HTML report generation, and error handling.

## Project Structure

```text
ReconGuard/
├── reconguard.py
├── tests/
│   ├── __init__.py
│   ├── test_reconguard.py
│   └── fixtures/
├── examples/
│   └── sample_report.html
├── .gitignore
├── LICENSE
└── README.md
```

The following files and directories are generated at runtime and should not be committed with real scan data:

- `scan_history.json` — contains saved scan records.
- `reports/` — contains generated HTML reports.

## Limitations

- ReconGuard focuses on TCP port scanning.
- Service identification depends on Nmap's probes and the target's responses.
- Firewalls, filtering, host availability, and network conditions can affect results.
- Scan comparisons depend on the accuracy of recorded coverage metadata and scan results.
- An open port is not, by itself, proof of a vulnerability.
- Authorization flags do not independently verify permission.

## Roadmap

Potential future improvements include:

- Additional automated tests for malformed and option-like targets.
- More robust scan timeout and error-handling tests.
- Improved report presentation and sanitized example reports.
- Additional scan-comparison and coverage edge cases.

## Responsible Use

ReconGuard is intended for educational use, authorized security assessments, and controlled lab environments.

Use it only on systems you own or have explicit permission to test. Follow applicable laws, organizational policies, and the target owner's rules.

## License

Released under the MIT License. See `LICENSE` for details.
