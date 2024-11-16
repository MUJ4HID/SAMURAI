import requests
import socket
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import re


class SAMURAI:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.startswith("http") else f"http://{target_url}"
        self.hostname = urlparse(self.target_url).hostname
        self.results = {}

    def get_ip_address(self):
        """Retrieve the IP address of the target hostname."""
        try:
            ip = socket.gethostbyname(self.hostname)
            self.results['IP Address'] = ip
        except socket.gaierror:
            self.results['IP Address'] = "Could not resolve IP"

    def check_reachability(self):
        """Verify if the target URL is reachable."""
        try:
            response = requests.get(self.target_url, timeout=5)
            self.results['Reachable'] = "Yes" if response.status_code == 200 else "No"
        except requests.RequestException as e:
            self.results['Reachable'] = f"Error: {e}"

    def detect_http_methods(self):
        """Check for enabled HTTP methods on the server."""
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "TRACE", "CONNECT", "PATCH"]
        enabled_methods = []
        for method in methods:
            try:
                response = requests.request(method, self.target_url, timeout=3)
                if response.status_code < 405:
                    enabled_methods.append(method)
            except requests.RequestException:
                pass
        self.results['HTTP Methods Enabled'] = enabled_methods or "None detected"

    def check_open_ports(self):
        """Scan for common open ports."""
        # Only check commonly used ports
        common_ports = [80, 443, 21, 22, 23, 25, 53, 110, 143]
        open_ports = []
        try:
            for port in common_ports:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(1)
                    result = sock.connect_ex((self.hostname, port))
                    if result == 0:  # Port is open
                        open_ports.append(port)
            self.results['Open Ports'] = open_ports or "None detected"
        except Exception as e:
            self.results['Open Ports'] = f"Error: {e}"

    def find_subdomains(self):
        """Search for potential subdomains."""
        subdomains = ["www", "mail", "ftp", "test", "api", "dev", "staging", "blog"]
        found = []
        for subdomain in subdomains:
            sub_url = f"http://{subdomain}.{self.hostname}"
            try:
                response = requests.get(sub_url, timeout=3)
                if response.status_code == 200:
                    found.append(sub_url)
            except requests.RequestException:
                pass
        self.results['Subdomains Found'] = found or "None detected"

    def extract_emails(self):
        """Extract email addresses from the target URL."""
        try:
            response = requests.get(self.target_url, timeout=5)
            emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", response.text)
            self.results['Email Addresses'] = list(set(emails)) or "None found"
        except requests.RequestException as e:
            self.results['Email Addresses'] = f"Error: {e}"

    def directory_scanning(self):
        """Scan for common directories on the target."""
        directories = ["/admin", "/login", "/backup", "/test", "/uploads"]
        found_dirs = []
        for directory in directories:
            url = self.target_url.rstrip("/") + directory
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:
                    found_dirs.append(url)
            except requests.RequestException:
                pass
        self.results['Directories Found'] = found_dirs or "None detected"

    def check_broken_access_control(self):
        """Test for Broken Access Control vulnerabilities."""
        test_urls = ["/admin", "/user", "/profile"]
        found = []
        for url in test_urls:
            response = requests.get(self.target_url.rstrip("/") + url, timeout=3)
            if response.status_code == 403:  # Forbidden, should not be accessible
                found.append(url)
        self.results['Broken Access Control'] = found or "None detected"

    def check_sensitive_data_exposure(self):
        """Test for Sensitive Data Exposure vulnerabilities."""
        response = requests.get(self.target_url, timeout=5)
        if 'password' in response.text.lower() or 'credit card' in response.text.lower():
            self.results['Sensitive Data Exposure'] = "Sensitive data found!"
        else:
            self.results['Sensitive Data Exposure'] = "No sensitive data exposed."

    def check_ssrf(self):
        """Test for Server-Side Request Forgery (SSRF) vulnerabilities."""
        test_payload = "http://localhost:80"
        response = requests.get(self.target_url + "?url=" + test_payload, timeout=3)
        if response.status_code == 200 and "localhost" in response.text:
            self.results['SSRF Vulnerability'] = "Potential SSRF vulnerability detected."
        else:
            self.results['SSRF Vulnerability'] = "No SSRF detected."

    def check_sql_injection(self):
        """Test for SQL Injection vulnerabilities."""
        test_payload = "' OR 1=1 --"
        response = requests.get(self.target_url + "?id=" + test_payload, timeout=3)
        if "syntax" in response.text or "mysql" in response.text:
            self.results['SQL Injection'] = "Possible SQL Injection detected."
        else:
            self.results['SQL Injection'] = "No SQL Injection detected."

    def check_xss(self):
        """Test for Cross Site Scripting (XSS) vulnerabilities."""
        test_payload = "<script>alert('XSS')</script>"
        response = requests.get(self.target_url + "?q=" + test_payload, timeout=3)
        if test_payload in response.text:
            self.results['XSS Vulnerability'] = "Possible XSS vulnerability detected."
        else:
            self.results['XSS Vulnerability'] = "No XSS detected."

    def check_broken_authentication(self):
        """Test for Broken Authentication vulnerabilities."""
        login_url = self.target_url.rstrip("/") + "/login"
        response = requests.get(login_url, timeout=3)
        if response.status_code == 200 and "login" in response.text:
            self.results['Broken Authentication'] = "Login page found - test login credentials."
        else:
            self.results['Broken Authentication'] = "No broken authentication found."

    def check_security_misconfiguration(self):
        """Test for Security Misconfiguration vulnerabilities."""
        headers = requests.head(self.target_url, timeout=3)
        if "Server" in headers and "X-Powered-By" in headers:
            self.results['Security Misconfiguration'] = "Server and powered-by headers exposed."
        else:
            self.results['Security Misconfiguration'] = "No misconfigurations detected."

    def check_brute_force_protection(self):
        """Test for protection against brute-force attacks."""
        login_url = self.target_url.rstrip("/") + "/login"
        response = requests.get(login_url, timeout=3)
        if response.status_code == 200 and "captcha" in response.text:
            self.results['Brute Force Protection'] = "Brute force protection found."
        else:
            self.results['Brute Force Protection'] = "No brute force protection detected."

    def run_all_scans(self):
        """Execute all scanning functions concurrently."""
        with ThreadPoolExecutor() as executor:
            executor.submit(self.get_ip_address)
            executor.submit(self.check_reachability)
            executor.submit(self.detect_http_methods)
            executor.submit(self.check_open_ports)
            executor.submit(self.find_subdomains)
            executor.submit(self.extract_emails)
            executor.submit(self.directory_scanning)
            executor.submit(self.check_broken_access_control)
            executor.submit(self.check_sensitive_data_exposure)
            executor.submit(self.check_ssrf)
            executor.submit(self.check_sql_injection)
            executor.submit(self.check_xss)
            executor.submit(self.check_broken_authentication)
            executor.submit(self.check_security_misconfiguration)
            executor.submit(self.check_brute_force_protection)

    def display_results(self):
        """Pretty-print the results in a bullet-point list."""
        print("\n=== SAMURAI Scan Results ===\n")
        for key, value in sorted(self.results.items()):
            if isinstance(value, list):  # List values are shown line-by-line
                print(f"• {key}:")
                for item in value:
                    print(f"   - {item}")
            else:
                print(f"• {key}: {value}")


if __name__ == "__main__":
    print(r"""
      ██████╗  █████╗ ███╗   ███╗██╗   ██╗██████╗  █████╗ ██╗
     ██╔════╝ ██╔══██╗████╗ ████║██║   ██║██╔══██╗██╔══██╗██║
     ╚█████╗  ███████║██╔████╔██║██║   ██║██████╔╝███████║██║
     ██╔══██╗ ██╔══██║██║╚██╔██║██║   ██║██╔══██╗██╔══██║██║
     ╚█████╔╝ ██║  ██║██║ ╚═╝ ██║╚██████╔╝██████╔╝██║  ██║██║
      ╚════╝  ╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝
    """)

    target_url = input("Enter the target URL: ")
    samurai = SAMURAI(target_url)
    samurai.run_all_scans()
    samurai.display_results()
