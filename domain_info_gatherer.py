import socket
import dns.resolver
import whois
import requests
import ssl
import OpenSSL
import urllib.request
import urllib.parse
import urllib.error
import urllib.robotparser

def get_domain_info(domain):
    print("Domain Information:")

    # Get IP address
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"\nIP Address: {ip_address}")
        print("-"*80)
    except socket.gaierror:
        print("Unable to get IP address")
        print("-"*80)

    # Get DNS records
    try:
        dns_records = dns.resolver.resolve(domain, 'A')
        print("\nDNS Records:")
        for rdata in dns_records:
            print(f"  {rdata}")
        print("-"*80)
    except dns.resolver.NoAnswer:
        print("No DNS records found")
        print("-"*80)

    # Get server details
    try:
        response = requests.head(f"http://{domain}", timeout=5)
        print("\nServer Details:")
        print(f"  Server: {response.headers.get('Server')}")
        print(f"  Content Type: {response.headers.get('Content-Type')}")
        print(f"  Status Code: {response.status_code}")
        print("-"*80)
    except requests.exceptions.RequestException:
        print("Unable to get server details")
        print("-"*80)

    # Get request information
    try:
        url = f"http://{domain}"
        parsed_uri = urllib.parse.urlparse(url)
        domain_name = parsed_uri.netloc
        ssl_info = ssl.get_server_certificate((domain_name, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, ssl_info)
        print("\nRequest Information:")
        print(f"  Issuer: {x509.get_issuer().CN}")
        print(f"  Subject: {x509.get_subject().CN}")
        print(f"  Not Before: {x509.get_notBefore().decode('utf-8')}")
        print(f"  Not After: {x509.get_notAfter().decode('utf-8')}")
        print("-"*80)
    except Exception as e:
        print(f"Unable to get request information: {e}")
        print("-"*80)

    # Get port information
    try:
        print("\nPort Information:")
        for port in [80, 443]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((domain, port))
            if result == 0:
                print(f"  Port {port} is open")
            else:
                print(f"  Port {port} is closed")
            sock.close()
        print("-"*80)
    except Exception as e:
        print(f"Unable to get port information: {e}")
        print("-"*80)

    # Get WHOIS information
    try:
        whois_info = whois.whois(domain)
        print("\nWHOIS Information:")
        print(f"  Registrant: {whois_info.registrant}")
        print(f"  Registrar: {whois_info.registrar}")
        print(f"  Creation Date: {whois_info.creation_date}")
        print(f"  Expiration Date: {whois_info.expiration_date}")
        print("-"*80)
    except whois.parser.PywhoisError:
        print("Unable to get WHOIS information")
        print("-"*80)

    # Check robots.txt
    try:
        robot_parser = urllib.robotparser.RobotFileParser()
        robot_parser.set_url(f"http://{domain}/robots.txt")
        robot_parser.read()
        print("\nRobots.txt Information:")
        print(f"  Allow: {robot_parser.can_fetch('*', f'http://{domain}/')}")
        print("-"*80)
    except Exception as e:
        print(f"Unable to get robots.txt information: {e}")
        

if __name__ == "__main__":
    print("\n" + "="*40 + " Domain Info Gatherer Tool " + "="*40 + "\n")
    
    domain = input("Enter a domain: ")
    get_domain_info(domain)