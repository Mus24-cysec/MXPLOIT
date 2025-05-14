# MXPLOIT - Advanced Web Vulnerability Scanner

![MXPLOIT Banner](banner.png)

A comprehensive security tool for detecting XSS, SQL Injection, and Open Redirect vulnerabilities in web applications.

## Features

- **XSS Scanner**: Detects Cross-Site Scripting vulnerabilities with DOM-based verification
- **SQL Injection Detector**: Identifies SQLi vulnerabilities using error-based and time-based techniques
- **Open Redirect Checker**: Tests for unsafe URL redirections
- **Multi-threaded Scanning**: Fast parallel scanning capabilities
- **Custom Payload Support**: Load payloads from external files
- **Interactive Interface**: Color-coded console output

## Installation

### Prerequisites
- Python 3.8+
- Chrome/Chromium (for XSS detection)
- Git

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/mxploit.git
cd mxploit

# Install dependencies
pip install -r requirements.txt

# Install ChromeDriver (for XSS scanning)
python -m webdrivermanager chrome
