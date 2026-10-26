"""
scanner.py - Basic Vulnerability Scanner (beginner project)

Checks a target for:
  1. Open ports (common ones)
  2. Missing HTTP security headers
  3. Outdated / information-leaking software versions

IMPORTANT: Only scan systems you own or have permission to test.
This tool is limited to localhost / private addresses by default.

Usage examples:
    python scanner.py                       (scans 127.0.0.1:8080)
    python scanner.py --host 127.0.0.1 --port 8080
"""
import argparse
import re
import socket
import ipaddress
import http.client

# Common ports and what they usually are
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8000: "HTTP-alt", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

# Ports that are risky if left open
RISKY_PORTS = {
    21: "FTP sends data unencrypted. Use SFTP instead.",
    23: "Telnet is unencrypted. Use SSH instead.",
    445: "SMB exposed can be abused by worms. Block it from outside.",
    3306: "Database port open. Only allow trusted/local access.",
    3389: "RDP is a common attack target. Use VPN + strong passwords.",
    5432: "Database port open. Only allow trusted/local access.",
}

# Headers a secure site should send, plus the fix for each
SECURITY_HEADERS = {
    "Content-Security-Policy": "Add a CSP header to help block XSS attacks.",
    "X-Frame-Options": "Add 'X-Frame-Options: DENY' to prevent clickjacking.",
    "X-Content-Type-Options": "Add 'X-Content-Type-Options: nosniff'.",
    "Strict-Transport-Security": "Add HSTS so browsers always use HTTPS.",
    "Referrer-Policy": "Add a Referrer-Policy to limit data leaked to other sites.",
}

# Very simple "outdated version" rules: (software name, minimum safe version)
MIN_VERSIONS = {
    "apache": (2, 4, 0),
    "nginx": (1, 18, 0),
    "php": (7, 4, 0),
    "openssl": (1, 1, 1),
}


def is_local_target(host):
    """Safety check: only allow localhost or private IPs."""
    if host == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_loopback or ip.is_private
    except Exception:
        return False


def scan_ports(host):
    findings, open_ports = [], []
    print(f"\n[1/3] Scanning {len(COMMON_PORTS)} common ports on {host} ...")
    for port, name in COMMON_PORTS.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((host, port)) == 0:
            open_ports.append(port)
            print(f"   OPEN  {port:<5} ({name})")
            if port in RISKY_PORTS:
                findings.append(("HIGH", f"Risky port {port}/{name} is open", RISKY_PORTS[port]))
        s.close()
    if not open_ports:
        print("   No common ports open.")
    return findings, open_ports


def fetch_headers(host, port):
    try:
        conn = http.client.HTTPConnection(host, port, timeout=3)
        conn.request("GET", "/")
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
        return headers
    except Exception as e:
        print(f"   Could not connect over HTTP: {e}")
        return None


def check_headers(headers):
    findings = []
    print("\n[2/3] Checking security headers ...")
    for header, fix in SECURITY_HEADERS.items():
        if header.lower() in headers:
            print(f"   OK       {header}")
        else:
            print(f"   MISSING  {header}")
            findings.append(("MEDIUM", f"Missing header: {header}", fix))
    return findings


def parse_version(text):
    """Find 'name/1.2.3' patterns like Apache/2.2.15 in a string."""
    return re.findall(r"([A-Za-z\-]+)/(\d+)\.(\d+)(?:\.(\d+))?", text)


def check_versions(headers):
    findings = []
    print("\n[3/3] Checking software versions ...")
    banner_text = " ".join(headers.get(h, "") for h in ("server", "x-powered-by"))
    matches = parse_version(banner_text)
    if not matches:
        print("   No version info exposed (good!).")
        return findings
    for name, a, b, c in matches:
        version = (int(a), int(b), int(c or 0))
        vstr = ".".join(map(str, version))
        print(f"   Found {name} {vstr}")
        findings.append(("LOW", f"Server reveals software version: {name} {vstr}",
                         "Hide version info in your server config."))
        minimum = MIN_VERSIONS.get(name.lower())
        if minimum and version < minimum:
            findings.append(("HIGH", f"Outdated software: {name} {vstr}",
                             f"Upgrade to {'.'.join(map(str, minimum))} or newer."))
    return findings


def print_report(host, findings):
    print("\n" + "=" * 60)
    print(f"  VULNERABILITY REPORT for {host}")
    print("=" * 60)
    if not findings:
        print("  No issues found. Nice!")
        return
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    for level, issue, fix in sorted(findings, key=lambda f: order[f[0]]):
        print(f"\n  [{level}] {issue}")
        print(f"     Suggestion: {fix}")
    counts = {l: sum(1 for f in findings if f[0] == l) for l in order}
    print("\n" + "-" * 60)
    print(f"  Total: {len(findings)} issues "
          f"(High: {counts['HIGH']}, Medium: {counts['MEDIUM']}, Low: {counts['LOW']})")


def main():
    parser = argparse.ArgumentParser(description="Basic vulnerability scanner")
    parser.add_argument("--host", default="127.0.0.1", help="target host (local only)")
    parser.add_argument("--port", type=int, default=8080, help="web port to check")
    args = parser.parse_args()

    if not is_local_target(args.host):
        print("Refusing to scan: only localhost/private addresses are allowed.")
        print("Only scan systems you own or have permission to test.")
        return

    print(f"Starting scan of {args.host}:{args.port}")
    findings, open_ports = scan_ports(args.host)

    if args.port in open_ports or fetch_headers(args.host, args.port) is not None:
        headers = fetch_headers(args.host, args.port) or {}
        findings += check_headers(headers)
        findings += check_versions(headers)
    else:
        print(f"\nWeb server not reachable on port {args.port}. Did you start test_server.py?")

    print_report(args.host, findings)


if __name__ == "__main__":
    main()
