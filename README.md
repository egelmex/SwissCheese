# SwissCheese
Previously known as 'CertificateScanner'. Migrated due to underlying functionality change.

```
usage: swisscheese.py [-h] [-r IPRANGE [IPRANGE ...]]
                      [-t HOSTNAME [HOSTNAME ...]] [-p PORTNUM [PORTNUM ...]]
                      [-f FILE_IMPORT] [-x] [--timeout TIMEOUT]
                      [--default-ssl] [--path PATH_SCAN [PATH_SCAN ...]]

SwissCheese Web Server Scanner

optional arguments:
  -h, --help            show this help message and exit
  -r IPRANGE [IPRANGE ...], --range IPRANGE [IPRANGE ...]
                        IP address and CIDR range input. Multiple arguments
                        can be entered by separating them with spaces: E.g.
                        "-r 192.168.0.0/24 172.16.0.3 10.0.0.0/8".
  -t HOSTNAME [HOSTNAME ...], --host HOSTNAME [HOSTNAME ...]
                        Domain name of target host: E.g. "-t ins1gn1a.com"
  -p PORTNUM [PORTNUM ...], --port PORTNUM [PORTNUM ...]
                        Ports to use in the scan. Multiple ports can be
                        separated with spaces: E.g. "-p 8080 3389 443".
  -f FILE_IMPORT, --file FILE_IMPORT
                        Import the targets from a file. These can either be
                        individual IP addresses or CIDR ranges but must be one
                        per line.
  -x, --xml             Store output in an XML format for parsing into other
                        applications.
  --timeout TIMEOUT     Specify the maximum timeout in seconds allowed for
                        connectivity checks. Default value is set to 4
                        seconds. Lower values are less accurate.
  --default-ssl         Enable this option in place of -p to use the most
                        common SSL/TLS ports
  --path PATH_SCAN [PATH_SCAN ...]
                        Enter the URI path for header checking: E.g. "--path
                        login.php" for https://test.com/login.php
```
## Example Output

```
 ____          _          ____ _                         
/ ___|_      _(_)___ ___ / ___| |__   ___  ___  ___  ___ 
\___ \ \ /\ / / / __/ __| |   | '_ \ / _ \/ _ \/ __|/ _ \
 ___) \ V  V /| \__ \__ \ |___| | | |  __/  __/\__ \  __/
|____/ \_/\_/ |_|___/___/\____|_| |_|\___|\___||___/\___|
_________________________________________ Version 1.0.0 _


[*] 66.228.46.122:443 - ins1gn1a.com
[*] Cert: sha256WithRSAEncryption - ICA: sha384WithRSAEncryption
		[-] SSLv3 is Not Supported.
		[-] TLSv1.0 is Not Supported.
		[-] TLSv1.1 is Supported.
		[-] TLSv1.2 is Supported.
	[*] Forward Secrecy is supported.

[*] URI Path: /
	[*] HTTP Public Key Pinning is supported:
		[*] 		pin-sha256="wXbLzu1H1P1DKCwINgLk4mmeoUd+IwQ8v4Kxey35obM="
		[*] 		pin-sha256="nl30q/LLzDilu0AFWRMy6En0iwkiOIMaWkBxui0RRf0="
		[*] 		max-age=31536000
		[*] 		includeSubDomains
	[*] Content Security Policy is not set.
	[*] X-Frame-Options is set:
		[*] 		SAMEORIGIN
	[*] X-XSS-Protection is not set.
	[*] Strict-Transport-Security is set:
		[*] 		max-age=31536000
		[*] 		includeSubdomains
		[*] 		HSTS Preload is not configured.

[*] URI Path: /other-things/
	[*] HTTP Public Key Pinning is supported:
		[*] 		pin-sha256="wXbLzu1H1P1DKCwINgLk4mmeoUd+IwQ8v4Kxey35obM="
		[*] 		pin-sha256="nl30q/LLzDilu0AFWRMy6En0iwkiOIMaWkBxui0RRf0="
		[*] 		max-age=31536000
		[*] 		includeSubDomains
	[*] Content Security Policy is not set.
	[*] X-Frame-Options is set:
		[*] 		SAMEORIGIN
	[*] X-XSS-Protection is not set.
	[*] Strict-Transport-Security is set:
		[*] 		max-age=31536000
		[*] 		includeSubdomains
		[*] 		HSTS Preload is not configured.
```
