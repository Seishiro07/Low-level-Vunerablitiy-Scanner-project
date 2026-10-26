# Low-level-Vunerablitiy-Scanner-project
Basic Vulnerability Scanner: a Python tool that scans a locally hosted test site for open ports, missing security headers (CSP, HSTS, X-Frame-Options), and outdated software versions, then generates a report with fixes.

# Cybersecurity Beginner Tasks

Needs Python 3 only (no installs).

## Task 01 - Basic Vulnerability Scanner
Open two terminals in `task1_vuln_scanner/`:

    python test_server.py     # terminal 1: starts a deliberately weak local site
    python scanner.py         # terminal 2: scans it and prints a report

Checks: open ports, missing security headers, outdated/leaked software versions.
Only works on localhost/private addresses (scan only what you own!).
