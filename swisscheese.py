#!/usr/bin/env python3

# Modules
from time import gmtime, strftime
import ipaddress
import sys
import os
import argparse
import socket
import subprocess
import time
import traceback
from urllib.request import urlopen
import ssl
import http.client

# Colour Class
class clr:
    green = '\033[92m'
    yellow = '\033[93m'
    red = '\033[91m'
    std = '\033[0m'

banner = 	  (" ____          _          ____ _                         \n")
banner = banner + ("/ ___|_      _(_)___ ___ / ___| |__   ___  ___  ___  ___ \n")
banner = banner + ("\___ \ \ /\ / / / __/ __| |   | '_ \ / _ \/ _ \/ __|/ _ \\\n")
banner = banner + (" ___) \ V  V /| \__ \__ \ |___| | | |  __/  __/\__ \  __/\n")
banner = banner + ("|____/ \_/\_/ |_|___/___/\____|_| |_|\___|\___||___/\___|\n")
banner = banner + ("_________________________________________ Version 1.0.0 _\n")

# Global for persistent SSL/TLS usage (I know, I know...)
global ssl_v

# Argument inputs
parser = argparse.ArgumentParser(description='SwissCheese Web Server Scanner')
parser.add_argument('-r','--range',dest='iprange',help='IP address and CIDR range input. Multiple arguments can be entered by separating them with spaces: E.g. "-r 192.168.0.0/24 172.16.0.3 10.0.0.0/8".',required=False,nargs='+')
parser.add_argument('-t','--host',dest='hostname',help='Domain name of target host: E.g. "-t ins1gn1a.com"',required=False,nargs='+')
parser.add_argument('-p','--port',dest='portnum',help='Ports to use in the scan. Multiple ports can be separated with spaces: E.g. "-p 8080 3389 443".',required=False,nargs="+")
parser.add_argument('-f','--file',dest='file_import',help='Import the targets from a file. These can either be individual IP addresses or CIDR ranges but must be one per line.',required=False)
parser.add_argument('-x','--xml',dest='xml_output',help='Store output in an XML format for parsing into other applications.',required=False,default=False,action='store_true')
parser.add_argument('--timeout',dest='timeout',help='Specify the maximum timeout in seconds allowed for connectivity checks. Default value is set to 4 seconds. Lower values are less accurate.',required=False,default=4,type=int)
parser.add_argument('--default-ssl',dest='ssl',help='Enable this option in place of -p to use the most common SSL/TLS ports',action='store_true',default=False)
parser.add_argument('--path',dest='path_scan',help='Enter the URI path for header checking: E.g. "--path login.php" for https://test.com/login.php',required=False,nargs="+")
args = parser.parse_args()

# Argument > Variables
timeout = args.timeout
ip_range = args.iprange
ports = args.portnum
output = args.xml_output
hosts = args.hostname
path_scan = args.path_scan
global cert_bool

# Missing input
if not ports and not args.ssl:
    sys.exit(clr.red + "[*]" + clr.std + "Error: Port(s) must be selected either with -p [portnumber] or by using --default-ssl.")

if not path_scan:
    path_scan = "/"

# Variable
xml = ""
current_time = strftime("scan_result_%Y-%m-%d_%H-%M", gmtime())

#### Functions

# OpenSSL command which Greps for 'Signature Algorithm'
def check_cert(a,port):
    cmd = ("openssl s_client -showcerts -connect " + str(a) + ":" + str(port) + " < /dev/null 2> /dev/null | openssl x509 -noout -text 2> /dev/null | grep 'Signature Algorithm' | cut -d ' ' -f 7 | uniq")
    return os.popen(cmd).read()

# Retrieves the Intermediate Certificate Authority certificate.
def check_ica_cert(a,p,t):
    get_ica = ('openssl s_client -showcerts -connect ' + str(a) + ':' + str(p) + ' </dev/null 2>/dev/null | openssl x509 -text | grep "CA Issuers - URI:" | cut -d ":" -f 2,3 | xargs wget --quiet -O /tmp/server.crt 2>/dev/null')
    os.popen(get_ica)
    try:
        time.sleep(t)
    except KeyboardInterrupt:
        sys.exit(clr.red + "[*]" + clr.std + "Exiting...")
    read_ica = ('openssl x509 -inform DER -outform PEM -in /tmp/server.crt -text -noout </dev/null 2>/dev/null | grep "Signature Algorithm" | cut -d " " -f 7 | uniq')
    return os.popen(read_ica).read()

def check_ssl_tls(a,p,x):
    scrn_out = "\r"
    vuln_count = 0
    get_ssl3 = os.popen('openssl s_client -ssl3 -connect ' + str(a) + ':' + str(p) + ' </dev/null 2>/dev/null | grep "Cipher is (NONE)"').read()
    get_tls1 = os.popen('openssl s_client -tls1 -connect ' + str(a) + ':' + str(p) + ' </dev/null 2>/dev/null | grep "Cipher is (NONE)"').read()
    get_tls1_1 = os.popen('openssl s_client -tls1_1 -connect ' + str(a) + ':' + str(p) + ' </dev/null 2>/dev/null | grep "Cipher is (NONE)"').read()
    get_tls1_2 = os.popen('openssl s_client -tls1_2 -connect ' + str(a) + ':' + str(p) + ' </dev/null 2>/dev/null | grep "Cipher is (NONE)"').read()

    # SSL3
    if len(str(get_ssl3.rstrip())) == 0:
        scrn_out = scrn_out.rstrip() + (clr.red + "\t\t[-] " + clr.std + "SSLv3 is Supported.")
    else:
        scrn_out = scrn_out + (clr.green + "\t\t[-] " + clr.std + "SSLv3 is Not Supported.")
    
    # TLS1.0
    if len(str(get_tls1.rstrip())) == 0:
        scrn_out = scrn_out + (clr.yellow + "\n\t\t[-] " + clr.std + "TLSv1.0 is Supported.")
    else:
        scrn_out = scrn_out + (clr.green + "\n\t\t[-] " + clr.std + "TLSv1.0 is Not Supported.")

    # TLS 1.1
    if len(str(get_tls1_1.rstrip())) == 0:
        scrn_out = scrn_out + (clr.green + "\n\t\t[-] " + clr.std + "TLSv1.1 is Supported.")
    else:
        scrn_out = scrn_out + (clr.red + "\n\t\t[-] " + clr.std + "TLSv1.1 is Not Supported.")
        vuln_count += 1

    # TLS 1.2
    if len(str(get_tls1_2.rstrip())) == 0:
        scrn_out = scrn_out + (clr.green + "\n\t\t[-] " + clr.std + "TLSv1.2 is Supported.")
    else:
        scrn_out = scrn_out + (clr.red + "\n\t\t[-] " + clr.std + "TLSv1.2 is Not Supported.")
        vuln_count += 1

    # XML Output
    if (vuln_count == 2) and (x):
        host_by_ip = (socket.gethostbyaddr(str(a)))[0]
        xml = ("\n<item><ipaddress>" + str(a) + "</ipaddress><hostname>" + str(host_by_ip) + "</hostname><port>" + str(p) + "</port><vulnid>SC-1946</vulnid><latest_discovery>The service on " + str(a) + ":" + str(p) + " does not support TLS1.1 or TLS1.2, which are the recommended modern SSL/TLS Protocols to use for secure communications</latest_discovery></item>. ")
        with open(current_time + ".xml",'a') as xml_file:
            xml_file.write(xml)

    return scrn_out

def get_headers(a,p,x,uri_list):

    ## Generic header thingies
    for uri_path in uri_list:
        print (clr.green + "\n[*] " + clr.std + "URI Path: " + clr.green + str(uri_path))
        try:
            response = (urlopen("https://" + a + ":" + p + uri_path))
#            headers = response.getheaders()
        
        except:
            print (clr.red + "\t[*] " + clr.std + "Cannot retrieve page headers. Verify manually.")
            return

        headers = response.getheaders()
        header_count = 0
        h_pin = ""
        h_csp = ""
        h_click = ""
        h_xss = ""
        h_hsts = ""
        pin_count = 0
        csp_count = 0
        click_count = 0
        xss_count = 0
        hsts_count = 0

        while header_count < (len(headers)):
            if "Public-Key-Pins" == headers[header_count][0]:
                h_pin = (headers[header_count][1]).split(";")
            if "Content-Security-Policy" == headers[header_count][0]:
                h_csp = (headers[header_count][1]).split(";")
            if "X-Frame-Options" == headers[header_count][0]:
                h_click = (headers[header_count][1]).split(";")
            if "X-XSS-Protection" == headers[header_count][0]:
                h_xss = (headers[header_count][1]).split(";")
            if "Strict-Transport-Security" == headers[header_count][0]:
            	h_hsts = (headers[header_count][1]).split(";")
            # Something Else
            header_count += 1

        if len(h_pin) == 0:
            pin_count += 1
            print (clr.red + "\t[*] " + clr.std + "HTTP Public Key Pinning is not supported.")
        else:
            print (clr.green + "\t[*] " + clr.std + "HTTP Public Key Pinning is supported:" + clr.std)
            for pin in h_pin:
                if "pin-" in pin:
                    print (clr.green + "\t\t[*] " + clr.std + "\t\t" + clr.green + pin.strip() + clr.std)
                else:
                    print (clr.green + "\t\t[*] " + clr.std + "\t\t" + clr.green + pin.strip() + clr.std)

        if len(h_csp) == 0:
            csp_count += 1
            print (clr.yellow + "\t[*] " + clr.std + "Content Security Policy is not set.")
        else:
            print (clr.green + "\t[*] " + clr.std + "Content Security Policy is set:")
            for csp in h_csp:
                print (clr.green + "\t\t[*] " + clr.green + "\t\t" + csp.strip() + clr.std)

        if len(h_click) == 0:
            click_count += 1
            print (clr.red + "\t[*] " + clr.std + "X-Frame-Options is not set.")
        else:
            print (clr.green + "\t[*] " + clr.std + "X-Frame-Options is set:")
            for click in h_click:
                print (clr.green + "\t\t[*] " + clr.green + "\t\t" + click.strip() + clr.std)

        if len(h_xss) == 0:
            xss_count += 1
            print (clr.yellow + "\t[*] " + clr.std + "X-XSS-Protection is not set.")
        else:
            print (clr.green + "\t[*] " + clr.std + "X-XSS-Protection is set:")
            for xss in h_xss:
                print (clr.green + "\t\t[*] " + clr.green + "\t\t" + xss.strip() + clr.std)
                
        if len(h_hsts) == 0:
            hsts_count += 1
            print (clr.yellow + "\t[*] " + clr.std + "Strict-Transport-Security is not set.")
        else:
            print (clr.green + "\t[*] " + clr.std + "Strict-Transport-Security is set:")
            for hsts in h_hsts:
                if not "preload" == hsts.strip():
                    hsts_preload = True
                print (clr.green + "\t\t[*] " + clr.green + "\t\t" + hsts.strip() + clr.std)
            if hsts_preload:
                print (clr.yellow + "\t\t[*] " + clr.std + "\t\tHSTS Preload is not configured." + clr.std)

        if pin_count > 0 and x:
            ip_by_host = socket.gethostbyname(a)
            xml = ("\n<item><ipaddress>" + str(ip_by_host) + "</ipaddress><hostname>" + str(socket.gethostbyaddr(a)[0]) + "</hostname><port>" + str(p) + "</port><vulnid>SC-1972</vulnid><latest_discovery>The host web service does not support HTTP Public Key Pinning.</latest_discovery></item>. ")
            with open(current_time + ".xml",'a') as xml_file:
                xml_file.write(xml)
        if csp_count > 0 and x:
            ip_by_host = socket.gethostbyname(a)
            xml = ("\n<item><ipaddress>" + str(ip_by_host) + "</ipaddress><hostname>" + str(socket.gethostbyaddr(a)[0]) + "</hostname><port>" + str(p) + "</port><vulnid>SC-1975</vulnid><latest_discovery>The host web service does not return the Content-Security-Policy header.</latest_discovery></item>. ")
            with open(current_time + ".xml",'a') as xml_file:
                xml_file.write(xml)
        if click_count > 0 and x:
            ip_by_host = socket.gethostbyname(a)
            xml = ("\n<item><ipaddress>" + str(ip_by_host) + "</ipaddress><hostname>" + str(socket.gethostbyaddr(a)[0]) + "</hostname><port>" + str(p) + "</port><vulnid>SC-1803</vulnid><latest_discovery>The host does not return the X-Frame-Options header.</latest_discovery></item>. ")
            with open(current_time + ".xml",'a') as xml_file:
                xml_file.write(xml)
        if xss_count > 0 and x:
            ip_by_host = socket.gethostbyname(a)
            xml = ("\n<item><ipaddress>" + str(ip_by_host) + "</ipaddress><hostname>" + str(socket.gethostbyaddr(a)[0]) + "</hostname><port>" + str(p) + "</port><vulnid>SC-1802</vulnid><latest_discovery>The host web service does return the X-XSS-Protection header.</latest_discovery></item>. ")
            with open(current_time + ".xml",'a') as xml_file:
                xml_file.write(xml)                
    return

# Specified port connection is verified prior to certificate retrieval.
def check_port(a,p,t):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(t)
        result = s.connect((str(a), int(p)))
        s.close()
        return True
    except KeyboardInterrupt:
        sys.exit(clr.red + "[*]" + clr.std + "Exiting...")
    # Port is closed.
    except:
        return False
    return True

# Main function, which calls the others. Cycles iteratively through hosts:ports.
def search_range(r,ps,xml,xo,t):
    vuln_id = ""
    x_count = 0
    # Fetch certificates from target
    try:
        cert = check_cert(str(ip),port).rstrip()
    except:
        cert = False
    # Output to stdout
    if cert:
        scrn_out = (clr.green + "\n[*] " + clr.std + str(ip) + ":" + str(port) + clr.green + " - " + clr.std + str(host_by_ip + "\n"))
        if 'sha1' in cert:
            hashclr = clr.red
            vuln_id = "SC-1929"
            x_count += 1
        elif 'md5' in cert:
            hashclr = clr.red
            vuln_id = "SC-1957"
            x_count += 1
        else:
            hashclr = clr.green
        # Set XML variable
        if x_count > 0:
            xml = ("\n<item><ipaddress>" + str(ip) + "</ipaddress><hostname>" + str(host_by_ip) + "</hostname><port>" + str(port) + "</port><vulnid>" + vuln_id + "</vulnid><latest_discovery>The service on " + str(ip) + ":" + str(port) + " has a certficate signed using a weak algorithm. ")
        try:
            ica_cert = check_ica_cert(str(ip),port,t).rstrip()
        except:
            ica_cert = False
        ica_alg = ""

        if ica_cert:
            if (ica_cert == "sha1WithRSAEncryption") or (ica_cert == "md5WithRSAEncryption"):
                ica_alg = (clr.std + " - ICA: " + clr.red + ica_cert + clr.std)
                xml = xml + ("The intermediate certificate is signed using a weak algorithm.</latest_discovery></item>")
            else:
                ica_alg = (clr.std + " - ICA: " + clr.green + ica_cert + clr.std)
                xml = xml + ("</latest_discovery></item>")
        else:
            xml = xml + ("</latest_discovery></item>")
        scrn_out = scrn_out + (clr.green + "[*] " + clr.std + "Cert: " + hashclr + cert + ica_alg)
        os.popen("rm /tmp/server.crt  </dev/null 2>/dev/null")

        if ((x_count > 0) and (xo)):
            with open(current_time + ".xml",'a') as xml_file:
                xml_file.write(xml)
        return (scrn_out, True)

    else:
        scrn_out = scrn_out + (clr.red + "[*]" + clr.std + " Cannot retrieve certificate. Port may not be SSL/TLS.\n")
        return (scrn_out, False)

# Hostname main function, which calls the others. Cycles iteratively through hosts:ports.
def search_host(name,p,xml,x,t):
    vuln_id = ""
    x_count = 0
    try:
        ip_by_host = socket.gethostbyname(name)
    except:
        ip_by_host = "Cannot retrieve IP Address"
    try:
        cert = (check_cert(name,port)).strip()
    except:
        cert = ""
    # Output to stdout
    scrn_out = (clr.green + "\n[*] " + clr.std + str(ip_by_host) + ":" + str(port) + clr.green + " - " + clr.std + str(name) + "\n")
    if cert:
        if (str(cert) == "sha1WithRSAEncryption"):
            hashclr = clr.red
            vuln_id = "SC-1929"
            x_count += 1

        elif (str(cert) == "md5WithRSAEncryption"):
            hashclr = clr.red
            vuln_id = "SC-1957"
            x_count += 1
        else:
            hashclr = clr.green

        # Set XML variable
        if x_count > 0:
            xml = ("\n<item><ipaddress>" + str(ip_by_host) + "</ipaddress><hostname>" + str(name) + "</hostname><port>" + str(port) + "</port><vulnid>" + vuln_id + "</vulnid><latest_discovery>The service on " + str(name) + ":" +str(port) + " has a certficate signed using a weak algorithm. ")

        # Fetch ICA certificate if server certificate exists
        try:
            ica_cert = (check_ica_cert(name,port,t)).strip()
        except:
            ica_cert = False
        ica_alg = ""
        if ica_cert:
            if (str(ica_cert) == "sha1WithRSAEncryption") or (str(ica_cert) == "md5WithRSAEncryption"):
                ica_alg = (clr.std + " - ICA: " + clr.red + str(ica_cert) + clr.std)
                xml = xml + ("The intermediate certificate is signed using a weak algorithm.</latest_discovery></item>")
            else:
                ica_alg = (clr.std + " - ICA: " + clr.green + str(ica_cert) + clr.std)
                xml = xml + ("</latest_discovery></item>")
        else:
            xml = xml + ("</latest_discovery></item>")
        scrn_out = scrn_out + (clr.green + "[*] " + clr.std + "Cert: " + hashclr + (str(cert)).rstrip() + clr.std + ica_alg)

        os.popen("rm /tmp/server.crt  </dev/null 2>/dev/null")
        if x_count > 0 and x:
            with open(current_time + '.xml','a') as xml_file:
                xml_file.write(xml)
        return (scrn_out, True)
    else:
        scrn_out = scrn_out + (clr.red + "[*] " + clr.red + "Cannot retrieve certificate." + clr.std)
        return (scrn_out, False)

def check_fs(host,port,xml,x):
    cmd = 'openssl s_client -connect ' + host + ':' + port + ' -cipher EDH,EECDH </dev/null 2> /dev/null | grep "Cipher is ECDHE\|Cipher is DHE\|Verify Return Code: 20\|Verify Return Code: 18"'
    fs = os.popen(cmd).read()

    # XML Output, and FS Support Output Conditional
    if (len(fs) == 0):
        xml = ("\n<item><ipaddress>" + str(host) + "</ipaddress><port>" + str(port) + "</port><vulnid>SC-1953</vulnid><latest_discovery>The service on " + str(host) + ":" +str(port) + " does not support Forward Secrecy on any ECDHE or DHE ciphers.</latest_discovery></item>")
        if x:
            with open(current_time + '.xml','a') as xml_file:
                xml_file.write(xml)
        return False # Not supported
    else:
        return True # Supported

if __name__ == "__main__":

    # Banner Output
    print (banner)

    # Set input ports to 'Default' SSL/TLS ports
    if args.ssl:
        ports = ["22","443","465","636","990","993","995","3389","5800","5900","8443"]

    # Run IP Address Scan
    if ip_range:
        # Address verification
        if "-" in str(ip_range):
            parser.print_help()
            print (clr.red + "\n[*] " + clr.std + "Start and end addresses are not supported.")
            sys.exit()

        for raw_range in ip_range:
            try:
                address_range = ipaddress.ip_network(raw_range)
                for ip in address_range:
                    ip = str(ip)
                    try:
                        host_by_ip = (socket.gethostbyaddr(str(ip)))[0]
                    except:
                        host_by_ip = "Cannot perferm reverse DNS lookup."
                    for port in ports:
                        port = str(port)
                        if (check_port(ip,port,timeout)):
                            cert_output, cert_bool = search_range(address_range,port,xml,output,timeout)
                            print (cert_output)
                            if (cert_bool):
                                print (check_ssl_tls(ip,port,output).rstrip())
                                fs_supp = check_fs(ip,port,xml,output)
                                if (str(fs_supp) == "True") and (cert_bool):
                                    print (clr.green + "\t[*] " + clr.std + "Forward Secrecy is supported.")
                                elif (str(fs_supp) == "False") or (not cert_bool):
                                    print (clr.red + "\t[*] " + clr.std + "Forward Secrecy is not supported.")
                                get_headers(ip,port,output,path_scan)
            except:
                print (str(sys.exc_info()))
                break

        if output:
            print (clr.yellow + "\n[*] " + clr.std + "Output saved as XML in file " + clr.green + "./" + current_time + ".xml")

    # Run hostname check
    elif hosts:
        for host in hosts:
            try:
                ip_by_host = socket.gethostbyname(name)
            except:
                ip_by_host = "Cannot retrieve IP Address"
            for port in ports:
                if (check_port(host,port,timeout)):
                    cert_output, cert_bool = search_host(host,port,xml,output,timeout)
                    print (cert_output)
                    if (cert_bool):
                        # stdout in-progress results
                        print (check_ssl_tls(host,port,output).rstrip())

			# Check for Forward Secrecy Support
                        fs_supp = check_fs(host,port,xml,output)
                        if (str(fs_supp) == "True") and (cert_bool):
                            print (clr.green + "\t[*] " + clr.std + "Forward Secrecy is supported.")
                        elif (str(fs_supp) == "False") or (not cert_bool):
                            print (clr.red + "\t[*] " + clr.std + "Forward Secrecy is not supported.")
                        #check_hpkp(host,port,output) ## HPKP Check
                        get_headers(host,port,output,path_scan)
        if output:
            print (clr.yellow + "\n[*] " + clr.std + "Output saved as XML in file " + clr.green + current_time + ".xml")

    # Run file input check
    elif args.file_import:
        with open(args.file_import) as temp:
            file_addresses = [line.rstrip('\n') for line in temp]

            # Iterate through each address per line
            for raw_line in file_addresses:
                if '/' not in raw_line:
                    for port in ports:
                        if (check_port(raw_line,port,timeout)):
                            cert_output, cert_bool = search_host(raw_line,port,xml,output,timeout)
                            print (cert_output)
                            if (cert_bool):
                                print (check_ssl_tls(raw_line,port,output).rstrip())
                                fs_supp = check_fs(raw_line,port,xml,output)
                                if (str(fs_supp) == "True") and (cert_bool):
                                    print (clr.green + "\t[*] " + clr.std + "Forward Secrecy is supported.")
                                elif (str(fs_supp) == "False") or (not cert_bool):
                                    print (clr.red + "\t[*] " + clr.std + "Forward Secrecy is not supported.")
                                get_headers(raw_line,port,output)
                elif '/' in raw_line:
                    for ip in address_range:
                        ip = str(ip)
                        try:
                            host_by_ip = (socket.gethostbyaddr(str(ip)))[0]
                        except:
                            host_by_ip = "Cannot perferm reverse DNS lookup."
                        for port in ports:
                            port = str(port)
                            if (check_port(ip,port,timeout)):
                                cert_output, cert_bool = search_range(address_range,port,xml,output,timeout)
                                print (cert_output)
                                if (cert_bool):
                                    print (check_ssl_tls(ip,port,output).rstrip())
                                    fs_supp = check_fs(ip,port,xml,output)
                                    if (str(fs_supp) == "True") and (cert_bool):
                                        print (clr.green + "\t[*] " + clr.std + "Forward Secrecy is supported.")
                                    elif (str(fs_supp) == "False") or (not cert_bool):
                                        print (clr.red + "\t[*] " + clr.std + "Forward Secrecy is not supported.")
                                    get_headers(ip,port,output)
    
    else:
        parser.print_help()
