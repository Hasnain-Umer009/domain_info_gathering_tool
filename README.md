# Domain Info Gatherer Tool

The Domain Info Gatherer Tool is a Python script designed to gather comprehensive information about a given domain. This tool is ideal for cybersecurity professionals and enthusiasts looking to perform preliminary reconnaissance and security assessments.

## Features

- IP Address Resolution: Retrieves the domain's IP address.
- DNS Records Fetching: Obtains DNS records for the domain.
- Server Details: Gathers server type, content type, and response status code.
- SSL Certificate Information: Extracts SSL certificate details, including issuer, subject, and validity period.
- Port Status Check: Scans common ports (80 and 443) to determine their status.
- WHOIS Information: Fetches registration details of the domain.
- Robots.txt Analysis: Checks and interprets the robots.txt file for web crawling permissions.

## Requirements

- Python 3
- dnspython
- python-whois
- requests
- pyopenssl

## Installation

1. Install the required packages using pip:

```bash
pip3 install dnspython python-whois requests pyopenssl

2)Save the script as domain_info_gatherer.py

## Usage
1)Run the script:
python3 domain_info_gatherer.py
2)Enter a domain when prompted to gather information about it.
