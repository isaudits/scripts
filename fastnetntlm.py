#!/usr/bin/env python

####################################################################################
# Orig Authors: Tim Medin & Dan Borkowski
# Description: An automated method of reading netntlm hashes and cracking them
####################################################################################

from __future__ import with_statement # Required in 2.5
from sys import *
import sys
import os
import time
import subprocess
import fileinput
from optparse import OptionParser
from optparse import OptionGroup
from datetime import datetime
from sets import Set
import signal
from contextlib import contextmanager

class AlreadyCracked(Exception): pass

#timeout code pulled from http://stackoverflow.com/questions/366682/how-to-limit-execution-time-of-a-function-call-in-python
class TimeoutException(Exception): pass

@contextmanager
def time_limit(seconds):
    def signal_handler(signum, frame):
        raise TimeoutException, "Timed out!"
    signal.signal(signal.SIGALRM, signal_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)

#originally SIGINT would occassionally require 'stty sane/reset'
def signal_handler(signal, frame):
        try:
                os.system("stty sane")
                sys.exit(0)
        except:
                sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

#set default file paths
path_perl = "/usr/bin/perl"
#path_johnnetntlm = "/usr/share/john/netntlm.pl" #default
path_johnnetntlm = "/usr/share/metasploit-framework/data/john/run.linux.x64.mmx/netntlm.pl" #kali
path_rcracki = "/usr/bin/rcracki_mt"
path_rt_alpha = "/opt/tables/rcracki_mt/Halflm_tables_alphanum"
path_rt_allspace = "/opt/tables/rcracki_mt/Halflm_tables_all-space"

usage = "usage: %prog [options] hash[or]hashfile"
parser = OptionParser(usage=usage, version="%prog 0.2")
parser.add_option("-a", "--alpha", action="store", type="string", dest="rt_alpha", help="path to halflmchall_alpha-numeric rainbow tables", default=path_rt_alpha)
parser.add_option("-b", "--all", action="store", type="string", dest="rt_allspace", help="path to halflmchall_all-space rainbow tables", default=path_rt_allspace)
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", help="print status messages", default=False)
parser.add_option("-o", "--output",        action="store", type="string", dest="output",        help="optional output file containing passwords", default=False)
parser.add_option("-t", "--timeout",        action="store",        type="int", dest="timeout",        help="optional timeout for bruteforcing the 7+ characters of a particular hash. If the timeout if reached, <timeout> will be outputted as the password", default=0)

group = OptionGroup(parser, "Suplementary executable locations", "If your file locations differ from the default use these options")
group.add_option("-p", "--perlpath", action="store", type="string", dest="perl", help="path to perl [default: %default]", default=path_perl)
group.add_option("-j", "--johnnetntlm", action="store", type="string", dest="johnnetntlm", help="path to John the Ripper's netntlm.pl from Jumbo Pack [default: %default]", default=path_johnnetntlm)
group.add_option("-r", "--rcracki", action="store", type="string", dest="rcracki", help="path to rcracki_mt [default: %default]", default=path_rcracki)
parser.add_option_group(group)

(options, args) = parser.parse_args()

# check that files/tools exist
if not os.path.exists(options.johnnetntlm):
        parser.error ("John's netntlm.pl does not exist")
if not os.path.exists(options.rcracki):
        parser.error ("rcracki does not exist")
if not os.path.exists(options.perl):
        parser.error ("Perl does not exist")

# put the rainbbow tables into a list
rtables = []
if options.rt_alpha:
        rtables.append(options.rt_alpha)
if options.rt_allspace:
        rtables.append(options.rt_allspace)
if len(rtables) == 0:
        parser.error("No rainbow tables specified")

# ensure an input file is specified
if len(args) == 0:
        parser.error("No hash or hash file specified")

# TODO: FIX THIS THE RIGHT WAY
#print "Make sure you copy the charset.txt file from the directory rcracki_mt runs in"

# open hashes file and remove duplidates
hashes = set([])
if os.path.exists(args[0]):
        fin = open(args[0],"r")
        for hashrow in fin:
                hashes.add(hashrow)
        fin.close()
elif args[0].count(":") == 4 or args[0].count(":") == 5:
        hashes.add(args[0])
else:
        "Bad hash or hash file. Try again."
        parser.error("Bad hash or hash file. Try harder.")
        OptionParser.print_usage()

# crack away baby
for line in hashes:
        try:
                with time_limit(options.timeout):
                        if options.verbose: print "Processing " + line.replace("\n","")
                        if line.count(":") == 5:        
                                # parse the file
                                user = line.split(":")[0]
                                domain = line.split(":")[2]
                                lmhash = line.split(":")[3]
                                lmhash_first = lmhash[0:16]
                        elif line.count(":") == 4:
                                user = line.split(":")[0]
                                domain = line.split(":")[1]
                                lmhash = line.split(":")[3]
                                nthash = line.split(":")[4].replace("\n","")
                                lmchal = line.split(":")[2]
                                lmhash_first = lmhash[0:16]
                                line = user+"::"+domain+":"+lmhash+":"+nthash+":"+lmchal+"\n"
                                if options.verbose: print "Looks like Cain format. Converting to John "+line.replace("\n","")
                        else:
                                print "Unknown hash format. Exiting..."
                                sys.exit(0)

                        #check for and skip computer accounts
                        if "$" in user:
                                print domain + "/" + user + " looks like a computer account. Skipping."
                                continue                        

                        #check output file to see if hash has already been cracked
                        if options.output and os.path.exists(options.output):
                                outfile = open(options.output,'r')
                                for lineoutput in outfile:
                                        if user in lineoutput:
                                                if options.verbose: print user + " has already been cracked. Skipping\n"
                                                raise AlreadyCracked

                        if options.verbose: print str(datetime.now()) + ": Processing " + user + " with tables " + rtables[0]
                        process = subprocess.Popen(options.rcracki + " -h " + lmhash_first + " " + rtables[0], shell=True, stdout=subprocess.PIPE)
                        lastline = process.communicate()[0].splitlines()[-1]
                        seed = lastline.split()[1]
                        if options.verbose: print str(datetime.now()) + ": Processing " + user + " seed: " + seed

                        if seed == "<notfound>" and len(rtables) == 2:
                                if options.verbose: print str(datetime.now()) + ": Processing " + user + " with tables " + rtables[0]
                                process = subprocess.Popen(options.rcracki + " -h " + lmhash_first + " " + rtables[1], shell=True, stdout=subprocess.PIPE)
                                lastline = process.communicate()[0].splitlines()[-1]
                                seed = lastline.split()[1]
                                if options.verbose: print str(datetime.now()) + ": Processing " + user + " seed: " + seed

                        if seed != "<notfound>":
                                singlehashfile = domain + "." + user + ".hash"
                                fout = open(singlehashfile, "w")
                                fout.write(line)
                                fout.close()

                                if options.verbose: print str(datetime.now()) + ": Bruteforcing the remainder of " + user + "'s password " + seed
                                process = subprocess.Popen(options.perl + " " + options.johnnetntlm + " --seed \'" + seed + "\' --file \'" + singlehashfile + "\'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                #if options.verbose: print str(datetime.now()) + "Running: " + options.perl + " " + options.johnnetntlm + " --seed \'" + seed + "\' --file " + singlehashfile)
                                out = process.communicate()
                                #print "out=%s" % (out,)

                                
                                #pull case insensitive password out of output and feed it as the seed of the same command
                                for line in out[0].splitlines():
                                        if line.find("(" + user +")") > 0:
                                                seed = line.split()[0]        
                                process = subprocess.Popen(options.perl + " " + options.johnnetntlm + " --seed \'" + seed + "\' --file \'" + singlehashfile + "\'", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                out = process.communicate()
                                #print "out=%s" % (out,)
                                # check the output. the first part looks for a new crack
                                passwd = None
                                for line in out[0].splitlines():
                                        if line.find("(" + user +")") > 0:
                                                passwd = line.split()[0]
                                                #print "passwd=" + passwd                                

                                # if the password was previously found use this to extract it from the output
                                if not passwd:
                                        for line in out[0].splitlines():
                                                if line.find(user) > 0:
                                                        passwd = line.split(":")[1]
                                                        #pass =print domain + " " + user + " " + line.split()[0]
                                                        #print "passwd=" + passwd
                                if not passwd:
                                        print "Running netntlm.pl failed. John output:"
                                        print "out=%s" % (out,)
                                        sys.exit(0)
                        elif seed == "<notfound>":
                                print "Cannot find seed in rainbow tables for" + domain + "/" + user
                                passwd = "<notfound>"

        except TimeoutException, msg:
                passwd="<timeout>"
        except AlreadyCracked, msg:
                continue

        print domain + "/" + user + " " + passwd
        if options.output:
                        outputfile = open(options.output,'a')
                        outputfile.write(domain + "/" + user + " " + passwd + "\n")
                        outputfile.close()
                        #print passwd
        try:
                os.remove(singlehashfile)
        except:
                pass