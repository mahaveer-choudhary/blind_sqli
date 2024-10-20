# Blind SQL Injection (SQLi) Testing Tool

A Python-based Blind SQL Injection testing tool designed to detect and exploit SQLi vulnerabilities in URLs. It uses custom payloads to scan multiple URLs concurrently, handles WAF detection, and provides a detailed report of vulnerabilities discovered.

## Features

- **WAF Detection**: Detects Web Application Firewalls (WAF) such as Cloudflare, Akamai, ModSecurity, etc., before testing for vulnerabilities.
- **Multi-threaded Scanning**: Tests multiple URLs and payloads concurrently using a specified number of threads, speeding up the vulnerability scanning process.
- **Custom Payloads**: Allows the use of custom SQLi payloads provided via a file.
- **Response Time Analysis**: Determines SQLi vulnerability based on response time analysis.
- **Graceful Shutdown**: Implements signal handling for graceful shutdowns and saves results if interrupted.
- **Cookie Support**: Provides an option to include cookies during testing for authenticated scans.
- **User-Agent Randomization**: Randomizes the `User-Agent` header to simulate different browsers during testing.

## Prerequisites

Before you begin, ensure you have the following installed on your system:

- Python 3.x
- Python packages (Install via `pip`):

   ```bash
   pip install requests colorama prompt_toolkit rich
