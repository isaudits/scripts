#!/usr/bin/python

'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Convert password hash files among Cain/L0phtcrack, PwDump, and Metasploit formats
'''

import sys
import argparse

def main(argv):
    
    parser = argparse.ArgumentParser(description='Convert NTLM hash file among LC / Cain, PWDump, and msf formats.')
    parser.add_argument("infile", action="store", help="Input file")
    parser.add_argument("outfile", action="store", help="Output file to be generated")
    parser.add_argument("outformat", help="Output file format (pwdump, lc, msf)", nargs='?', default="pwdump")
    
    args = parser.parse_args()  
    
    inputfile = file(args.infile, "r")
    outputfile = file(args.outfile, "w")
    outformat = args.outformat
    
    response = raw_input("\nDelete machine accounts if detected (machine accounts end with a $)? [no]")
    if "y" in response or "Y" in response:
        remove_machines = True
    else:             
        remove_machines = False
    
    #pwdump format - <user>:<id>:<lanman pw>:<NT pw>:comment:homedir:
    # username:1001:AAD3B435B51404EEAAD3B435B51404EE:0A1E55D87719539687E73602FF486676:<comments>:<homedir>:
    
    #metasploit format - <user>:<id>:<lanman pw>:<NT pw>    (same as pwdump but without last 3 columns)
    # username:1001:AAD3B435B51404EEAAD3B435B51404EE:0A1E55D87719539687E73602FF486676
    
    #lc format - <user>:<???>:<???>:<lanman pw>:<NT pw>    
    # username:"":"":AAD3B435B51404EEAAD3B435B51404EE:0A1E55D87719539687E73602FF486676
    
    
    #Open up input file as test (separate instance) and read first line to determine the format; based on number of colons as separators
    testfile = file(args.infile, "r")
    testline = testfile.readline()
    numseparators = testline.count(":")
    if numseparators == 6:
        informat = "pwdump"
    elif numseparators == 4:
        informat = "lc"
    elif numseparators == 3:
        informat = "msf"
    else:
        print "Invalid input file!"
        sys.exit()
    testfile.close()
    print "input file format is " + informat      
    

    for line in inputfile:
            
        line = line.rstrip()
        line = line.split(":")
        
        if informat == "pwdump" or informat == "msf":
            username = line[0]
            lmhash = line[2]
            nthash = line[3]
        elif informat == "lc":
            username = line[0]
            lmhash = line[3]
            nthash = line[4]
        else:
            print "invalid line in file - aborting!"
            sys.exit()
            
        pwdump = username + '::' + lmhash + ':' + nthash + ':::'
        lc = username + ':"":"":' + lmhash + ':' + nthash
        
        if remove_machines == True and username.count("$") > 0:
            pass
        elif outformat == "pwdump":
            outputfile.write(pwdump + '\n')
            print pwdump
        elif outformat == "lc":
            outputfile.write(lc + '\n')
            print lc
        else:
            print "invalid format specified"
            sys.exit()

if __name__ == "__main__":
    main(sys.argv[1:])
