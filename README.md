SAMURAI Web Security Scanner

SAMURAI is an advanced web security scanner designed to identify and report common vulnerabilities on websites. The scanner checks for a variety of vulnerabilities described in the OWASP Top 10, including SQL Injection, Cross-Site Scripting (XSS), and many more. The bot uses multithreading to run tests in parallel, delivering results quickly.

Features
Multithreading: All scans run simultaneously to minimize scan time.
Vulnerability Testing: Checks for the most common vulnerabilities, including:
Broken Access Control (A01)
Sensitive Data Exposure (A02)
SQL Injection (A03)
Cross-Site Scripting (XSS) (A03)
Server-Side Request Forgery (SSRF) (A10)
Broken Authentication (A07)
Security Misconfiguration (A05)
Brute Force Protection (A07)
Email Extraction: Extracts all email addresses from the target website.
Open Ports: Checks for open ports on the target website.
Subdomain Discovery: Finds possible subdomains of the target website.
Directory Scan: Checks for common accessible directories like /admin, /login, etc.
Installation
Clone the repository:

bash
Copy code
git clone https://github.com/MUJ4HID/SAMURAI-Scanner.git
cd SAMURAI-Scanner
Install dependencies:

Install the required Python libraries:

bash
Copy code
pip install -r requirements.txt
If you don't have the requirements.txt file, you can manually install the following libraries:

bash
Copy code
pip install requests
Run the bot:

After installing the dependencies, you can run the bot by executing:

bash
Copy code
python samurai_scanner.py
Enter the target URL when prompted.

Usage
Enter the target URL: When you start the bot, you will be asked for a URL to scan. The scanner will then begin analyzing the website.
View Results: The scanner will output a detailed list of found vulnerabilities and potential security issues, including email addresses, open ports, and other relevant information.
Example Output:
less
Copy code
=== SAMURAI Scan Results ===

• IP Address: 192.168.1.1
• Reachable: Yes
• HTTP Methods Enabled:
   - GET
   - POST
• Open Ports: [80, 443]
• Subdomains Found:
   - http://www.example.com
• Email Addresses: ['admin@example.com', 'contact@example.com']
• Directories Found:
   - http://example.com/admin
   - http://example.com/login
• Broken Access Control: ['/admin', '/user']
• Sensitive Data Exposure: No sensitive data exposed.
...
Supported Vulnerability Tests
The scanner checks for the following vulnerabilities:

Broken Access Control (A01)
Sensitive Data Exposure (A02)
Server-Side Request Forgery (SSRF) (A10)
SQL Injection (A03)
Cross-Site Scripting (XSS) (A03)
Broken Authentication (A07)
Security Misconfiguration (A05)
Insufficient Protection from Brute Force Attacks (A07)
Example
Run the bot with the target URL http://example.com:

bash
Copy code
python samurai_scanner.py
Enter the URL http://example.com when prompted, and the bot will begin scanning the website.

Notes
The bot uses Requests and Sockets to scan for vulnerabilities.
All tests focus on common HTTP methods and vulnerabilities, making it useful for web administrators and developers.
Please note that the bot is not intended for attacks or malicious use. Use this scanner only on websites where you have explicit permission to test for vulnerabilities.
Contributing
If you find a bug or want to suggest an improvement, feel free to open an Issue or a Pull Request. All contributions are welcome!

License
This code is licensed under the MIT License. See the LICENSE file for more details.

Additional Notes:
Make sure you don't perform tests on websites you do not have explicit permission to test, as this could be illegal.