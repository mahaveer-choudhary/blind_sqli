
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
- Python packages (Install via `pip`)

## How to Use

### Clone the Repository:

```bash
git clone https://github.com/mahaveer-choudhary/blind_sqli.git
cd blind_sqli
```
### Install requirements

```bash
pip3 install -r requirements.txt
```
### Run the Script:

You can run the script directly using Python. It will prompt you to provide an input file containing URLs, payloads, and other parameters.

```bash
python3 blind_sqli.py
```

### Input Options:

- **URL Input**: You can provide a file containing URLs to scan or input a single URL manually.
- **Payloads**: A file containing custom SQLi payloads is required.
- **Cookie (Optional)**: If your scan requires authentication, you can provide a cookie string.
- **Number of Threads**: You can specify the number of concurrent threads (default is 5).
<img src="images/logo.png" alt="loading error" width="1000px">
The tool will scan each URL with the given payloads and detect any SQLi vulnerabilities based on the server's response time.

### WAF Detection:

The tool also detects whether a WAF is protecting the target URL and reports the WAF name if detected.
<img src="images/blured-detection-image.png" alt="loading error" width="1000px">

### Saving Results:

At the end of the scan, you'll be prompted to save vulnerable URLs into a text file.
<img src="images/summery.png" alt="loading error" width="1000px">

## Example Usage
- **Input URLs**: You will be prompted to input a file with the URLs to scan.
- **Payload File**: You will be asked for the file containing SQLi payloads.
- **WAF Detection**: Automatically detects WAF presence on each domain.
- **Thread Count**: You can specify the number of threads to use.

### Sample Input File Format

- **URL File**: A plain text file where each line contains one URL to be tested.

   ```plaintext
   https://example.com/index.php?id=1
   https://test.com/page?param=value
   ```

- **Payload File**: A plain text file with SQLi payloads, one per line.

   ```plaintext
   ' OR 1=1 --
   ' UNION SELECT null, null --
   ```

## Handling Interruptions

The tool supports safe interruption using `Ctrl+C`. If the tool is interrupted during a scan, it will attempt to save any detected vulnerable URLs before shutting down gracefully.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
