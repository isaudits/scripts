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
    parser.add_argument("-v","--verbose", action="store_true", help="verbose - show all ike-scan output")
    parser.add_argument("-a", "--alltransforms", action="store_true", help="show all responses, even if only notify response")
    parser.add_argument("--showbackoff", action="store_true", help="Show backoff (for fingerprinting)")
    parser.add_argument("--aggressive", action="store_true", help="Use IKE aggressive mode instead of main mode")
    parser.add_argument("--pskcrack", action="store", help="Output aggressive mode PSK in pskcrack format to output file")
    parser.add_argument("--id", action="store", help="specify id to pass in aggressive mode handshake (Sonicwall default is 'GroupVPN'; Cisco default is peer IP)")
    parser.add_argument("--idtype", action="store", help="specify id type to pass in aggressive mode handshake (e.g. 1)")
    parser.add_argument("--scanall", action="store_true", help="continue scanning through all transforms; default is to stop after first handshake recd")
    parser.add_argument("--allresponses", action="store_true", help="show all responses, even if only notify response")
    
    
    args = parser.parse_args()  
    
    target_ip = args.target_ip
        
    if os.getuid()!=0:
        print("Need root privileges to function properly; Re-run as sudo...")
        sys.exit()
    
    # Encryption algorithms: 
    if args.alltransforms:
        list_enc=['1','2', '3', '4', '5', '6', '7/128', '7/192', '7/256', '8']
    else:
        list_enc=['1', '5', '7/128', '7/192', '7/256']      #DES, Triple-DES, AES/128, AES/192 and AES/256
    # Hash algorithms: 
    if args.alltransforms:
        list_hash=['1','2', '3', '4', '5', '6']
    else:
        list_hash=['1','2']                                 #MD5 and SHA1
    # Authentication methods: 
    if args.alltransforms:
        list_auth=['1','2', '3', '4', '5', '6', '7', '8', '64221', '65001']
    else:
        list_auth=['1','3', '64221', '65001']               #Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
    # Diffie-Hellman groups: 
    if args.alltransforms:
        list_dhgroup=['1','2', '3', '4', '5', '6', '7', '8', '9', '10', '11','12', '13', '14', '15', '16', '17', '18']
    else:
        list_dhgroup=['1','2', '5']                         #1, 2 and 5
    
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
                        
                    if args.idtype:
                        ikescan_command = ikescan_command + " --idtype=" + args.idtype
                    
                    p = subprocess.Popen(ikescan_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
                    p.wait()
                    out,err = p.communicate()
                    exitcode = p.returncode
                    
                    regex_notify = '[1-9][0-9]* returned notify'         #displays all results with returned responses (even notify)
                    regex_handshake = '[1-9][0-9]* returned handshake'      #only displays results returning handshake
                    regex_cisco = 'Cisco'
                    regex_ciscodpd = 'Dead Peer'
                    
                    if args.verbose:
                        matchObj = True
                    elif args.allresponses:
                        matchObj = re.search(regex_notify, out)
                    else:
                        matchObj = re.search(regex_handshake, out)          
                                                           
                    if matchObj:
                        print ikescan_command + "\n" + out
                        
                        #check to see if it is a cisco response that does not include dead peer detection
                        #payload - if this is the case, we may have specified a nonexistent ID
                        if re.search(regex_cisco, out) and not re.search(regex_ciscodpd, out):
                            print "WARNING - cisco response detected without Dead Peer Detection in payload."
                            print "Depending upon device version and patch status this could mean a bad group ID."
                            print "If this is true, psk-crack attempts will be unsuccessful!"
                        
                        #if not an extended scan and we got a handshake, exit program
                        if args.scanall == False and re.search(regex_handshake, out):
                            sys.exit()
                    
if __name__ == "__main__":
    main(sys.argv[1:])


