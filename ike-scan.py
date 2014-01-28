#!/usr/bin/env python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

ike-scan automation script
'''

import os
import sys
import subprocess
import argparse
import re

def main(argv):
    parser = argparse.ArgumentParser(description='Run ike-scan transforms against a target')
    parser.add_argument("target_ip", action="store", help="Target IP address")
    parser.add_argument("--showbackoff", action="store_true", help="Show backoff (for fingerprinting)")
    parser.add_argument("--aggressive", action="store_true", help="Use IKE aggressive mode instead of main mode")
    parser.add_argument("--pskcrack", action="store", help="Output aggressive mode PSK in pskcrack format with optional output file")
    parser.add_argument("--id", action="store", help="specify id to pass in aggressive mode handshake")
    parser.add_argument("--allresponses", action="store_true", help="show all responses, even if only notify response")
    
    args = parser.parse_args()  
    
    target_ip = args.target_ip
        
    if os.getuid()!=0:
        print("Need root privileges to function properly; Re-run as sudo...")
        sys.exit()
    
    # Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
    list_enc=['1', '5', '7/128', '7/192', '7/256']
    # Hash algorithms: MD5 and SHA1
    list_hash=['1','2']
    # Authentication methods: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
    list_auth=['1','3', '64221', '65001']
    # Diffie-Hellman groups: 1, 2 and 5
    list_dhgroup=['1','2', '5']
    
    for enc in list_enc:
        for hash in list_hash:
            for auth in list_auth:
                for dhgroup in list_dhgroup:
                    
                    ikescan_command = "ike-scan %s --trans=%s,%s,%s,%s -M" % (target_ip, enc, hash, auth, dhgroup)
                    if args.showbackoff:
                        ikescan_command = ikescan_command + " --showbackoff"
                        
                    if args.aggressive:
                        ikescan_command = ikescan_command + " --aggressive"
                        
                    if args.pskcrack:
                        ikescan_command = ikescan_command + " --pskcrack=" + args.pskcrack
                        
                    if args.id:
                        ikescan_command = ikescan_command + " --id=" + args.id
                    
                    p = subprocess.Popen(ikescan_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
                    out,err = p.communicate()
                    exitcode = p.returncode
                    
                    if args.allresponses:
                        regex_str = '[1-9][0-9]* returned'      #displays all results with returned responses (even notify)
                    else:
                        regex_str = 'shake returned'           #only displays results returning handshake
                    
                    matchObj = re.search(regex_str, out)                    
                    if matchObj:
                        print ikescan_command + "\n" + out
                        
if __name__ == "__main__":
    main(sys.argv[1:])


