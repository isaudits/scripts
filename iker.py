###############################################################################
### iker.py
### 
### This tool can be used to analyse the security of a IPsec based VPN.
### 
### This script is under GPL v3 License:
### 
###                                http://www.gnu.org/licenses/gpl-3.0.html
### 
### From a IP address/range or a list of them, iker.py uses ike-scan to 
### look for common misconfiguration in VPN concentrators.
### 
### In this version, iker does:
### 
### * VPNs discovering
### * check for IKE v2 support
### * vendor IDs (VID) extraction
### * implementation guessing (backoff)
### * list supported transforms in Main Mode
### * check aggressive mode and list supported transforms in this mode
### * enumerate valid client/group IDs in aggressive mode
### * analyse results to extract actual issues
### * support 2 output formats
### 
### FIXED BUGS / NEW FEATURES:
### 
### * Identify if ike-scan launches any error during the scan
### * Improved the GUI by adding a progressbar and the current transform
### * Skip feature
### * Capability to exit at any time saving results
### * Fixed a bug that did not identify IKE v2 when IKE v1 was not supported
### 
### How to use it? That's easy!
###
### # python iker.py -i ips.txt -o iker_output.txt -x iker_output.xml -v
### 
### Use -h option to complete help.
### 
### 
### Author: Julio Gomez Ortega (JGO@portcullis-security.com)
### 
###############################################################################

from sys import exit, stdout
from os import geteuid
import subprocess
import argparse
from re import sub
from time import localtime, strftime, sleep


###############################################################################

# iker version
VERSION = "1.1"

# ike-scan full path
FULLIKESCANPATH = "ike-scan"

# Verbose flag (default False)
VERBOSE = False

# Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
ENCLIST = []

# Hash algorithms: MD5 and SHA1
HASHLIST = []

# Authentication methods: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
AUTHLIST = []

# Diffie-Hellman groups: 1, 2 and 5
GROUPLIST = []

# Full algorithms lists
FULLENCLIST = ['1', '2', '3', '4', '5', '6', '7/128', '7/192', '7/256', '8']
FULLHASHLIST = ['1', '2', '3', '4', '5', '6']
FULLAUTHLIST = ['1', '2', '3', '4', '5', '6', '7', '8', '64221', '64222', '64223', '64224', '65001', '65002', '65003', '65004', '65005', '65006', '65007', '65008', '65009', '65010']
FULLGROUPLIST = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12', '13', '14', '15', '16', '17', '18']


# XML Output
XMLOUTPUT = "output.xml"

# Client IDs dictionary
CLIENTIDS = ""

# Delay between requests
DELAY = 0

# Flaws:
FLAWVPNDISCOVERABLEC = "\033[93m[+]\033[0m The IKE service could be discovered (Risk: LOW)"
FLAWIKEV2SUPPORTEDC = "\033[93m[+]\033[0m IKE v2 is supported (Risk: Informational)"
FLAWVPNFINGVIDC = "\033[93m[+]\033[0m The IKE service could be fingerprinted by analysing the vendor ID (VID) returned (Risk: LOW)"
FLAWVPNFINGBACKOFFC = "\033[93m[+]\033[0m The IKE service could be fingerprinted by analysing the responses received (Risk: LOW)"
FLAWWEAKENCALGC = "\033[93m[+]\033[0m The following weak encryption algorithm was supported: DES (Risk: MEDIUM)"
FLAWWEAKHASHALGC = "\033[93m[+]\033[0m The following weak hash algorithm was supported: MD5 (Risk: MEDIUM)"
FLAWWEAKDHGALGC = "\033[93m[+]\033[0m The following weak Diffie-Hellman group was supported: MODP-768 (Risk: MEDIUM)"
FLAWAGGRESSIVEC = "\033[93m[+]\033[0m Aggressive Mode was accepted by the IKE service (Risk: MEDIUM)"
FLAWAGGRGROUPNOENCC = "\033[93m[+]\033[0m Aggressive Mode transmits group name without encryption (Risk: LOW)"
FLAWCIDENUMERATIONC = "\033[93m[+]\033[0m Client IDs could be enumerated (Risk: MEDIUM)"

FLAWVPNDISCOVERABLE = "The IKE service could be discovered (Risk: LOW)"
FLAWIKEV2SUPPORTED = "IKE v2 is supported (Risk: Informational)"
FLAWVPNFINGVID = "The IKE service could be fingerprinted by analysing the vendor ID (VID) returned (Risk: LOW)"
FLAWVPNFINGBACKOFF = "The IKE service could be fingerprinted by analysing the responses received (Risk: LOW)"
FLAWWEAKENCALG = "The following weak encryption algorithm was supported: DES (Risk: MEDIUM)"
FLAWWEAKHASHALG = "The following weak hash algorithm was supported: MD5 (Risk: MEDIUM)"
FLAWWEAKDHGALG = "The following weak Diffie-Hellman group was supported: MODP-768 (Risk: MEDIUM)"
FLAWAGGRESSIVE = "Aggressive Mode was accepted by the IKE service (Risk: MEDIUM)"
FLAWAGGRGROUPNOENC = "Aggressive Mode transmits group name without encryption (Risk: LOW)"
FLAWCIDENUMERATION = "Client IDs could be enumerated (Risk: MEDIUM)"



###############################################################################
### Methods
###############################################################################

###############################################################################
def welcome ():
	'''This method prints a welcome message.'''
	
	print '''
iker v. %s

The ike-scan based script that checks for security flaws in IPsec-based VPNs.

                               by Julio Gomez ( jgo@portcullis-security.com )
''' % VERSION
	

###############################################################################
def checkPrivileges ():
	'''This method checks if the script was launched with root privileges.
	@return True if it was launched with root privs and False in other case.'''
	
	return geteuid() == 0

###############################################################################
def getArguments ():
	'''This method parse the command line.
	@return the arguments received and a list of targets.'''
	global VERBOSE
	global FULLIKESCANPATH
	global ENCLIST
	global HASHLIST
	global AUTHLIST
	global GROUPLIST
	global XMLOUTPUT
	global CLIENTIDS
	global DELAY
	
	targets = []
	
	parser = argparse.ArgumentParser()
	
	parser.add_argument("target", type=str, nargs='?', help="The IP address or the network (CIDR notation) to scan.")
	
	parser.add_argument("-v", "--verbose", action="store_true", help="Be verbose.")
	parser.add_argument("-d", "--delay", type=int, help="Delay between requests (in milliseconds). Default: 0 (No delay).")
	parser.add_argument("-i", "--input", type=str, help="An input file with an IP address/network per line.")
	parser.add_argument("-o", "--output", type=str, help="An output file to store the results.")
	parser.add_argument("-x", "--xml", type=str, help="An output file to store the results in XML format. Default: output.xml")
	parser.add_argument("--encalgs", type=str, default="1 5 7/128 7/192 7/256", help="The encryption algorithms to check. Default: DES, 3DES, AES/128, AES/192 and AES/256. Example: --encalgs=\"1 5 7/128 7/192 7/256\"")
	parser.add_argument("--hashalgs", type=str, default="1 2", help="The hash algorithms to check. Default: MD5 and SHA1. Example: --hashalgs=\"1 2\"")
	parser.add_argument("--authmethods", type=str, default="1 3 64221 65001", help="The authorization methods to check. Default: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH. Example: --authmethods=\"1 3 64221 65001\"")
	parser.add_argument("--dhgroups", type=str, default="1 2 5", help="The Diffie-Hellman groups to check. Default: MODP 768, MODP 1024 and MODP 1536. Example: --dhgroups=\"1 2 5\"")
	parser.add_argument("--fullalgs", action="store_true", help="Equivalent to: --encalgs=\"1 2 3 4 5 6 7/128 7/192 7/256 8\" --hashalgs=\"1 2 3 4 5 6\" --authmethods=\"1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010\" --dhgroups=\"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18\"")
	parser.add_argument("--ikepath", type=str, help="The FULL ike-scan path if it is not in the PATH variable and/or the name changed.")
	parser.add_argument("-c", "--clientids", type=str, help="A file (dictionary) with a client ID per line to enumerate valid client IDs in Aggressive Mode. Default: unset - This test is not launched by default.")
	
	args = parser.parse_args()
	
	if args.target:
		targets.append (args.target)
	
	if args.input:
		try:
			f = open (args.input, "r")
			targets.extend (f.readlines())
			f.close ()
		except:
			print "\033[91m[*]\033[0m The input file specified ('%s') could not be opened." % args.input
	
	if args.output:
		try:
			f = open (args.output, "w")
			f.close ()
		except:
			print "\033[91m[*]\033[0m The output file specified ('%s') could not be opened/created." % args.output
	
	if not targets:
		print "\033[91m[*]\033[0m You need to specify a target or an input file (-i)."
		parser.parse_args (["-h"])
		exit (1)
	
	if args.verbose:
		VERBOSE = True
	
	if args.ikepath:
		FULLIKESCANPATH = args.ikepath
	
	if args.encalgs:
		ENCLIST = args.encalgs.split()
		for alg in ENCLIST:
			parts = alg.split('/')
			for p in parts:
				if not p.isdigit():
					print "\033[91m[*]\033[0m Wrong syntax for the encalgs parameter. Check syntax."
					parser.parse_args (["-h"])
					exit (1)
	
	if args.hashalgs:
		HASHLIST = args.hashalgs.split()
		for alg in HASHLIST:
			if not alg.isdigit():
				print "\033[91m[*]\033[0m Wrong syntax for the hashalgs parameter. Check syntax."
				parser.parse_args (["-h"])
				exit (1)
	
	if args.authmethods:
		AUTHLIST = args.authmethods.split()
		for alg in AUTHLIST:
			if not alg.isdigit():
				print "\033[91m[*]\033[0m Wrong syntax for the authmethods parameter. Check syntax."
				parser.parse_args (["-h"])
				exit (1)
	
	if args.dhgroups:
		GROUPLIST = args.dhgroups.split()
		for alg in GROUPLIST:
			if not alg.isdigit():
				print "\033[91m[*]\033[0m Wrong syntax for the dhgroups parameter. Check syntax."
				parser.parse_args (["-h"])
				exit (1)
	
	if args.xml:
		XMLOUTPUT = args.xml
	try:
		f = open (XMLOUTPUT, "w")
		f.close ()
	except:
		print "\033[91m[*]\033[0m The XML output file could not be opened/created."
	
	if args.clientids:
		try:
			f = open (args.clientids, "r")
			f.close ()
			CLIENTIDS = args.clientids
		except:
			print "\033[91m[*]\033[0m The client ID dictionary could not be read. This test won't be launched."
	
	if args.delay:
		DELAY = args.delay
	
	if args.fullalgs:
		ENCLIST = FULLENCLIST
		HASHLIST = FULLHASHLIST
		AUTHLIST = FULLAUTHLIST
		GROUPLIST = FULLGROUPLIST
	
	return args, targets
	


###############################################################################
def printMessage (message, path=None):
	'''This method prints a message in the standard output and in the output file
	if it existed.
	@param message The message to be printed.
	@param path The output file, if specified.'''
	
	print message
	
	if path:
		try:
			f = open (path, "a")
			f.write ("%s\n" % message)
			f.close()
		except:
			pass



###############################################################################
def launchProccess (command):
	'''Launch a command in a different process and return the process.'''
	
	process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	
	error = process.stderr.readlines()
	if len(error) > 0 and "ERROR" in error[0] and "port 500" in error[0]:
		printMessage ("\033[91m[*]\033[0m Something was wrong! There may be another instance of ike-scan running. Ensure that there is no other proccess using ike-scan before to launch iker.")
		exit(1)
	
	return process


###############################################################################
def delay (time):
	'''This method wait for a delay.
	@param time The time to wait in milliseconds.'''
	
	if time:
		sleep ( time / 1000.0 )



###############################################################################
def waitForExit (args, vpns, ip, key, value):
	'''This method shows a progressbar during the discovery of transforms.
	@param top The total number of transforms combinations
	@param current The iteration within the bucle (which transform is checking).
	@param transform The string that represents the transform.'''

	try:
		printMessage("\033[91m[*]\033[0m You pressed Ctrl+C. Do it again to exit or wait to continue but skipping this step.")
		vpns[ip][key] = value
		sleep(2)
		if key not in vpns[ip].keys() or not vpns[ip][key]:
			printMessage("[*] Skipping test...", args.output)
	except KeyboardInterrupt:
		parseResults (args, vpns)
		printMessage ( "iker finished at %s" % strftime("%a, %d %b %Y %H:%M:%S +0000", localtime()), args.output )
		exit(0)



###############################################################################
def updateProgressBar (top, current, transform):
	'''This method shows a progressbar during the discovery of transforms.
	@param top The total number of transforms combinations
	@param current The iteration within the bucle (which transform is checking).
	@param transform The string that represent the transform.'''
	
	progressbar = "[....................] %d%% - Current transform: %s\r"
	tt = 20
	step = top / tt
	# Progress: [====================] 10% : DES-MD5
	cc = current / step
	progressbar = progressbar.replace(".", "=", cc)
	perctg = current * 100 / top
	
	#print progressbar % (perctg, transform),
	stdout.write(progressbar % (perctg, transform))
	stdout.flush()


###############################################################################
def checkIkeScan ():
	'''This method checks for the ike-scan location.
	@return True if ike-scan was found and False in other case.'''
	
	#proccess = launchProccess ("%s --version" % FULLIKESCANPATH)
	proccess = subprocess.Popen("%s --version" % FULLIKESCANPATH, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proccess.wait()
	
	output = proccess.stderr.read()
	
	if "ike-scan" in output.lower():
		return True
	else:
		return False


###############################################################################
def discovery (args, targets, vpns):
	'''Run ike-scan to discover IKE services and update the vpns variable with the information found.
	@param args The command line parameters
	@param targets The targets specified (IPs and/or networks)
	@param vpns A dictionary to store all the information'''
	
	printMessage ("[*] Discovering IKE services, please wait...", args.output)
	
	# Launch ike-scan for each target and parse the output
	for target in targets:
		
		process = launchProccess ("%s -M %s" % (FULLIKESCANPATH, target))
		process.wait()
		
		ip = None
		info = ""
		
		for line in process.stdout.readlines():
			#line = line[:-1]
			
			if not line.split() or "Starting ike-scan" in line or "Ending ike-scan" in line:
				continue
			
			if line[0].isdigit():
				
				if info:
					vpns[ip] = {}
					vpns[ip]["handshake"] = info.strip()
					
					if VERBOSE:
						printMessage (info, args.output)
					else:
						printMessage ("\033[92m[*]\033[0m IKE service identified at: %s" % ip, args.output)
				
				ip = line.split()[0]
				info = line
			else:
				info = info + line
			
		if info and ip not in vpns.keys():
			vpns[ip] = {}
			vpns[ip]["handshake"] = info.strip()
			if VERBOSE:
				printMessage (info, args.output)
			else:
				printMessage ("\033[92m[*]\033[0m IKE service identified at: %s" % ip, args.output)



###############################################################################
def checkIKEv2 (args, targets, vpns):
	'''This method checks if IKE version 2 is supported.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''
	
	printMessage ("[*] Checking for IKE version 2 support...", args.output)
	ips = []
	
	try:
		# Check the IKE v2 support
		for target in targets:
			
			process = launchProccess ("%s -2 -M %s" % (FULLIKESCANPATH, target))
			process.wait()
			
			ip = None
			info = ""
			
			for line in process.stdout.readlines():
				
				if not line.split() or "Starting ike-scan" in line or "Ending ike-scan" in line:
					continue
				
				if line[0].isdigit():
					
					if info:
						printMessage ("\033[92m[*]\033[0m IKE version 2 is supported by %s" % ip, args.output)
						ips.append(ip)
						if ip in vpns.keys():
							vpns[ip]["v2"] = True
						else:
							printMessage ("[*] IKE version 1 support was not identified in this host (%s). iker will not perform more tests against this host." % ip, args.output)

					ip = line.split()[0]
					info = line
				
			if info and ip not in ips:
				printMessage ("\033[92m[*]\033[0m IKE version 2 is supported by %s" % ip, args.output)
				if ip in vpns.keys():
					vpns[ip]["v2"] = True
				else:
					printMessage ("[*] IKE version 1 support was not identified in this host (%s). iker will not perform more tests against this host." % ip, args.output)
		
		# Complete those that don't support it
		for ip in vpns.keys():
			
			if "v2" not in vpns[ip].keys():
				vpns[ip]["v2"] = False
	except KeyboardInterrupt:
		waitForExit (args, vpns, ip, "v2", False)
	

###############################################################################
#def checkIKEv2 (args, targets, vpns):
	#'''This method checks if IKE version 2 is supported.
	#@param args The command line parameters
	#@param vpns A dictionary to store all the information'''
	
	#printMessage ("[*] Checking for IKE version 2 support...", args.output)
	
	#try:
		#for ip in vpns.keys():
			
			#vpns[ip]["v2"] = False
			
			#process = launchProccess ("%s -2 -M %s" % (FULLIKESCANPATH, ip))
			#process.wait()
			
			#for line in process.stdout.readlines():
				
				#if ip in line:
					#printMessage ("\033[92m[*]\033[0m IKE version 2 is supported by %s" % ip, args.output)
					#vpns[ip]["v2"] = True
					#break
	#except KeyboardInterrupt:
		#waitForExit (args, vpns, ip, "v2", False)
	

###############################################################################
def fingerprintVID (args, vpns, handshake=None):
	'''This method tries to discover the vendor of the devices by checking
	the VID. Results are written in the vpns variable.
	@param args The command line parameters
	@param vpns A dictionary to store all the information
	@param handshake The handshake where look for a VID'''
	
	for ip in vpns.keys():
		
		if "vid" not in vpns[ip].keys():
			vpns[ip]["vid"] = []
		
		# Fingerprint based on VIDs
		hshk = vpns[ip]["handshake"]
		if handshake:
			if ip in handshake:
				hshk = handshake
			else:
				continue
		
		transform = ""
		vid = ""
		for line in hshk.splitlines():
			
			if "SA=" in line:
				transform = line.strip()[4:-1]
			
			if "VID=" in line and "(" in line and ")" in line and "draft-ietf" not in line and "IKE Fragmentation" not in line and "Dead Peer Detection" not in line and "XAUTH" not in line and "RFC 3947" not in line and "Heartbeat Notify" not in line:
				
				vid = line[line.index('(')+1:line.index(')')]
		
		enc = False
		for pair in vpns[ip]["vid"]:
			if pair[0] == vid:
				enc = True
		
		if vid and not enc:
			vpns[ip]["vid"].append ( (vid, hshk) )
			
			printMessage ("\033[92m[*]\033[0m Vendor ID identified for IP %s with transform %s: %s" % (ip, transform, vid), args.output)


###############################################################################
def fingerprintShowbackoff (args, vpns, transform="", vpnip=""):
	'''This method tries to discover the vendor of the devices and the results
	are written in the vpns variable.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''
	
	printMessage ( "\n[*] Trying to fingerprint the devices%s. This proccess is going to take a while (1-5 minutes per IP). Be patient..." % (transform and " (again)" or transform) , args.output)
	
	try:
		for ip in vpns.keys():
			
			if vpnip and vpnip != ip:
				continue
			
			process = launchProccess ("%s --showbackoff %s %s" % (FULLIKESCANPATH, ((transform and ("--trans="+transform) or transform)), ip))
			vpns[ip]["showbackoff"] = ""
			process.wait()
			
			# Fingerprint based on the VPN service behaviour
			for line in process.stdout.readlines():
				
				if "Implementation guess:" in line:
					
					vendor = line[line.index('Implementation guess:')+22:].strip()
					
					if vendor.lower() != "unknown":
						
						vpns[ip]["showbackoff"] = vendor
					
						printMessage ("\033[92m[*]\033[0m Implementation guessed for IP %s: %s" % (ip, vendor), args.output)
			
			if not vpns[ip]["showbackoff"]:
				if transform:
					printMessage ("\033[91m[*]\033[0m The device %s could not been fingerprinted. It won't be retry again." % ip, args.output)
					vpns[ip]["showbackoff"] = " "
				else:
					printMessage ("\033[91m[*]\033[0m The device %s could not been fingerprinted because no transform is known." % ip, args.output)
	except KeyboardInterrupt:
		waitForExit (args, vpns, ip, "showbackoff", " ")


###############################################################################
def checkEncriptionAlgs (args, vpns):
	'''This method tries to discover accepted transforms. The results
	are written in the vpns variable.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''
	
	try:
		top = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
		current = 0
		for ip in vpns.keys():
			
			printMessage ( "\n[*] Looking for accepted transforms at %s" % ip, args.output)
			vpns[ip]["transforms"] = []
			
			for enc in ENCLIST:
				for hsh in HASHLIST:
					for auth in AUTHLIST:
						for group in GROUPLIST:
							
							process = launchProccess ("%s -M --trans=%s,%s,%s,%s %s" % (FULLIKESCANPATH, enc, hsh, auth, group, ip))
							process.wait()
							
							output = process.stdout.read()
							info = ""
							new = False
							for line in output.splitlines():
								
								if "Starting ike-scan" in line or "Ending ike-scan" in line or line.strip() == "":
									continue
								
								info += line + "\n"
								
								if "SA=" in line:
									new = True
									transform = line.strip()[4:-1]
									printMessage ("\033[92m[*]\033[0m Transform found: %s" % transform, args.output)
							
							if new:
								vpns[ip]["transforms"].append( ("%s,%s,%s,%s" % (enc,hsh,auth,group), transform, info) )
								fingerprintVID (args, vpns, info)
								# If the backoff could not been fingerprinted before...
								if not vpns[ip]["showbackoff"]:
									fingerprintShowbackoff (args, vpns, vpns[ip]["transforms"][0][0], ip)
							
							current += 1
							updateProgressBar(top, current, str(enc)+","+str(hsh)+","+str(auth)+","+str(group))
							delay (DELAY)
	except KeyboardInterrupt:
		if "transforms" not in vpns[ip].keys() or not vpns[ip]["transforms"]:
			waitForExit (args, vpns, ip, "transforms", [])
		else:
			waitForExit (args, vpns, ip, "transforms", vpns[ip]["transforms"])




###############################################################################
def checkAggressive (args, vpns):
	'''This method tries to check if aggressive mode is available. If so,
	it also store the returned handshake to a text file.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''
	
	try:
		top = len(ENCLIST) * len(HASHLIST) * len(AUTHLIST) * len(GROUPLIST)
		current = 0
		for ip in vpns.keys():
			
			printMessage ( "\n[*] Looking for accepted transforms in aggressive mode at %s" % ip, args.output)
			vpns[ip]["aggressive"] = []
			
			for enc in ENCLIST:
				for hsh in HASHLIST:
					for auth in AUTHLIST:
						for group in GROUPLIST:
							
							process = launchProccess ("%s -M --aggressive -P%s_handshake.txt --trans=%s,%s,%s,%s %s" % (FULLIKESCANPATH, ip, enc, hsh, auth, group, ip))
							process.wait()
							
							output = process.stdout.read()
							
							info = ""
							new = False
							for line in output.splitlines():
								
								if "Starting ike-scan" in line or "Ending ike-scan" in line or line.strip() == "":
									continue
								
								info += line + "\n"
								
								if "SA=" in line:
									new = True
									transform = line.strip()[4:-1]
									printMessage ("\033[92m[*]\033[0m Aggressive mode supported with transform: %s" % transform, args.output)
							
							if new:
								vpns[ip]["aggressive"].append( ("%s,%s,%s,%s" % (enc,hsh,auth,group), transform, info) )
								fingerprintVID (args, vpns, info)
								# If the backoff could not been fingerprinted before...
								if not vpns[ip]["showbackoff"]:
									fingerprintShowbackoff (args, vpns, vpns[ip]["aggressive"][0][0], ip)
							
							current += 1
							updateProgressBar(top, current, str(enc)+","+str(hsh)+","+str(auth)+","+str(group))
							delay (DELAY)
	except KeyboardInterrupt:
		if "aggressive" not in vpns[ip].keys() or not vpns[ip]["aggressive"]:
			waitForExit (args, vpns, ip, "aggressive", [])
		else:
			waitForExit (args, vpns, ip, "aggressive", vpns[ip]["aggressive"])



###############################################################################
def enumerateGroupIDCiscoDPD (args, vpns, ip):
	'''This method tries to enumerate valid client IDs from a dictionary.
	@param args The command line parameters
	@param vpns A dictionary to store all the information
	@param ip The ip where perform the enumeration'''
	
	# Check if possible
	
	process = launchProccess ("%s --aggressive --trans=%s --id=badgroupiker573629 %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], ip))
	process.wait()
	
	possible = True
	for line in process.stdout.readlines():
		if "dead peer" in line.lower():
			possible = False
			break
	
	if possible:
		delay(DELAY)
		
		# Enumerate users
		try:
			fdict = open (args.clientids, "r")
			cnt = 0
			
			for cid in fdict:
				cid = cid.strip()
				
				process = launchProccess ("%s --aggressive --trans=%s --id=%s %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], cid, ip))
				process.wait()
				
				output = process.stdout.readlines()[1].strip()
				
				# Check if the service is still responding 
				msg = sub (r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', output )
				if not msg:
					cnt += 1
					if cnt > 3:
						printMessage ( "\033[91m[*]\033[0m The IKE service cannot be reached; a firewall might filter your IP address. DPD Group ID enumeration could not be performed...", args.output)
						return False
				
				enc = False
				for line in output:
					if "dead peer" in line.lower():
						enc = True
						break
				
				delay (DELAY)
				
				# Re-check the same CID if it looked valid
				if enc:
					process = launchProccess ("%s --aggressive --trans=%s --id=%s %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], cid, ip))
					process.wait()
					
					enc = False
					for line in process.stdout.readlines():
						if "dead peer" in line.lower():
							vpns[ip]["clientids"].append(cid)
							printMessage ( "\033[92m[*]\033[0m A potential valid client ID was found: %s" % cid, args.output)
							break
					
					delay (DELAY)
			
			fdict.close()
		except:
			possible = False
	
	return possible



###############################################################################
def enumerateGroupID (args, vpns):
	'''This method tries to enumerate valid client IDs from a dictionary.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''
	
	if not args.clientids:
		return
	
	
	for ip in vpns.keys():
		
		vpns[ip]["clientids"] = []
		
		if not len (vpns[ip]["aggressive"]):
			continue
		
		printMessage ( "\n[*] Trying to enumerate valid client IDs for IP %s" % ip, args.output)
		
		# Check if the device is vulnerable to Cisco DPD group ID enumeration and exploit it
		done = False
		if "showbackoff" in vpns[ip].keys() and "cisco" in vpns[ip]["showbackoff"].lower():
			done = enumerateGroupIDCiscoDPD (args, vpns, ip)
		
		if "vid" in vpns[ip].keys() and len (vpns[ip]["vid"]) > 0:
			for vid in vpns[ip]["vid"]:
				if "cisco" in vid[0].lower():
					done = enumerateGroupIDCiscoDPD (args, vpns, ip)
					break
		
		if done:
			#if not len (vpns[ip]["clientids"]):
			continue # If Cisco DPD enumeration, continue
		
		# Try to guess the "unvalid client ID" message
		process = launchProccess ("%s --aggressive --trans=%s --id=badgroupiker123456 %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], ip))
		process.wait()
		message1 = sub (r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', process.stdout.readlines()[1].strip() )
		
		delay (DELAY)
		
		process = launchProccess ("%s --aggressive --trans=%s --id=badgroupiker654321 %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], ip))
		process.wait()
		message2 = sub (r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', process.stdout.readlines()[1].strip() )
		
		delay (DELAY)
		
		process = launchProccess ("%s --aggressive --trans=%s --id=badgroupiker935831 %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], ip))
		process.wait()
		message3 = sub (r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', process.stdout.readlines()[1].strip() )
		
		delay (DELAY)
		
		invalidmsg = ""
		if message1 == message2:
			invalidmsg = message1
			if message1 != message3:
				vpns[ip]["clientids"].append("badgroupiker935831")
		elif message1 == message3:
			invalidmsg = message1
			vpns[ip]["clientids"].append("badgroupiker654321")
		elif message2 == message3:
			invalidmsg = message2
			vpns[ip]["clientids"].append("badgroupiker123456")
		else:
			printMessage ( "\033[91m[*]\033[0m It was not possible to get a common response to invalid client IDs. This test will be skipped.", args.output)
			return
		
		# Enumerate users
		try:
			fdict = open (args.clientids, "r")
			cnt = 0
			
			for cid in fdict:
				cid = cid.strip()
				
				process = launchProccess ("%s --aggressive --trans=%s --id=%s %s" % (FULLIKESCANPATH, vpns[ip]["aggressive"][0][0], cid, ip))
				process.wait()
				msg = sub (r'(HDR=\()[^\)]*(\))', r'\1xxxxxxxxxxx\2', process.stdout.readlines()[1].strip() )
				
				if not msg:
					cnt += 1
					if cnt > 3:
						printMessage ( "\033[91m[*]\033[0m The IKE service cannot be reached; a firewall might filter your IP address. Skippig to the following service...", args.output)
						break
					
				elif msg != invalidmsg:
					vpns[ip]["clientids"].append(cid)
					printMessage ( "\033[92m[*]\033[0m A potential valid client ID was found: %s" % cid, args.output)
				
				delay (DELAY)
			
			fdict.close()
		except:
			pass
		
		
	
	

###############################################################################
def parseResults (args, vpns):
	'''This method analyses the results and prints them where correspond.
	@param args The command line parameters
	@param vpns A dictionary to store all the information'''
	
	
	printMessage ( "\n\nResults:\n--------", args.output)
	
	pathxml = XMLOUTPUT
	
	try:
		fxml = open (pathxml, "a")
		fxml.write ("<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<services>\n")
	except:
		pass
	
	for ip in vpns.keys():
		
		try:
			fxml.write ("\t<service ip=\"%s\">\n\t\t<flaws>\n" % ip)
		except:
			pass
		
		# Discoverable
		printMessage ( "\nResuls for IP %s:\n" % ip, args.output)
		printMessage ( "%s" % FLAWVPNDISCOVERABLEC, args.output)
		
		try:
			fxml.write ("\t\t\t<flaw flawid=\"1\" description=\"%s\"><![CDATA[%s]]></flaw>\n" % (FLAWVPNDISCOVERABLE, vpns[ip]["handshake"]) )
		except:
			pass
		
		
		# IKE v2
		if "v2" in vpns[ip].keys() and vpns[ip]["v2"]:
			printMessage ( "%s" % FLAWIKEV2SUPPORTEDC, args.output)
			
			try:
				fxml.write ("\t\t\t<flaw flawid=\"10\" description=\"%s\"></flaw>\n" % FLAWIKEV2SUPPORTED )
			except:
				pass
			
		
		# Fingerprinted by VID
		if "vid" in vpns[ip].keys() and len (vpns[ip]["vid"]) > 0:
			
			printMessage ( "%s" % FLAWVPNFINGVIDC, args.output)
			
			for pair in vpns[ip]["vid"]:
				
				printMessage ( "\t%s" % pair[0], args.output)
				if VERBOSE:
					printMessage ( "%s\n" % pair[1], args.output)
				
				try:
					fxml.write ("\t\t\t<flaw flawid=\"2\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (FLAWVPNFINGVID, pair[0], pair[1]) )
				except:
					pass
		
		# Fingerprinted by back-off
		if "showbackoff" in vpns[ip].keys() and vpns[ip]["showbackoff"].strip():
			
			printMessage ( "%s: %s" % (FLAWVPNFINGBACKOFFC, vpns[ip]["showbackoff"]), args.output)
			
			try:
				fxml.write ("\t\t\t<flaw flawid=\"3\" description=\"%s\" value=\"%s\"></flaw>\n" % (FLAWVPNFINGBACKOFF, vpns[ip]["showbackoff"]) )
			except:
				pass
		
		# Weak encryption/hash/DH group algorithm
		first = True
		if "transforms" in vpns[ip].keys():
			for trio in vpns[ip]["transforms"]:
				
				if "Enc=DES" in trio[1]:
					if first:
						first = False
						printMessage ( "%s" % FLAWWEAKENCALGC, args.output)
					
					if VERBOSE:
						printMessage ( "%s" % trio[2], args.output)
					
					try:
						fxml.write ("\t\t\t<flaw flawid=\"4\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (FLAWWEAKENCALG, trio[1], trio[2]) )
					except:
						pass
				
			first = True
			for trio in vpns[ip]["transforms"]:
				
				if "Hash=MD5" in trio[1]:
					if first:
						first = False
						printMessage ( "%s" % FLAWWEAKHASHALGC, args.output)
					
					if VERBOSE:
						printMessage ( "%s" % trio[2], args.output)
					
					try:
						fxml.write ("\t\t\t<flaw flawid=\"5\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (FLAWWEAKHASHALG, trio[1], trio[2]) )
					except:
						pass
				
			first = True
			for trio in vpns[ip]["transforms"]:
				
				if "Group=1:modp768" in trio[1]:
					if first:
						first = False
						printMessage ( "%s" % FLAWWEAKDHGALGC, args.output)
					
					if VERBOSE:
						printMessage ( "%s" % trio[2], args.output)
					
					try:
						fxml.write ("\t\t\t<flaw flawid=\"6\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (FLAWWEAKDHGALG, trio[1], trio[2]) )
					except:
						pass
		
		# Aggressive Mode ?
		if "aggressive" in vpns[ip].keys() and len (vpns[ip]["aggressive"]) > 0:
			
			printMessage ( "%s" % FLAWAGGRESSIVEC, args.output)
			
			for trio in vpns[ip]["aggressive"]:
				
				if VERBOSE:
					printMessage ( "%s" % (trio[2]), args.output)
				else:
					printMessage ( "\t%s" % (trio[1]), args.output)
				
				try:
					fxml.write ("\t\t\t<flaw flawid=\"7\" description=\"%s\" value=\"%s\"><![CDATA[%s]]></flaw>\n" % (FLAWAGGRESSIVE, trio[1], trio[2]) )
				except:
					pass
			
			printMessage ( "%s" % FLAWAGGRGROUPNOENCC, args.output)
			try:
				fxml.write ("\t\t\t<flaw flawid=\"8\" description=\"%s\"></flaw>\n" % (FLAWAGGRGROUPNOENC) )
			except:
				pass
			
		
		# Client IDs ?
		if "clientids" in vpns[ip].keys() and len (vpns[ip]["clientids"]) > 0:
			
			printMessage ( "%s: %s" % (FLAWCIDENUMERATIONC, ", ".join(vpns[ip]["clientids"])), args.output)
			
			try:
				fxml.write ("\t\t\t<flaw flawid=\"9\" description=\"%s\" value=\"%s\"></flaw>\n" % (FLAWCIDENUMERATION, ", ".join(vpns[ip]["clientids"])) )
			except:
				pass
		
		try:
			fxml.write ("\t\t</flaws>\n\t</service>\n")
		except:
			pass
		
		
	try:
		fxml.write ("</services>\n")
		fxml.close()
	except:
		pass
	



###############################################################################
### Main method of the application
###############################################################################

def main ():
	'''This is the main method of the application.'''
	
	# Say 'hello', check for privileges and ike-scan installation and parse the command line
	welcome ()
	
	if not checkPrivileges():
		print "\033[91m[*]\033[0m This script requires root privileges. Please, come back when you grow up."
		exit(0)
	
	vpns = {}
	args, targets = getArguments ()
	
	if not checkIkeScan():
		print "\033[91m[*]\033[0m ike-scan could not be found. Please specified the full path with the --ikepath option."
		exit(2)
	
	printMessage ( "Starting iker (http://labs.portcullis.co.uk/tools/iker) at %s" % strftime("%a, %d %b %Y %H:%M:%S +0000", localtime()), args.output )
	
	# 1. Discovery
	discovery ( args, targets, vpns )
	checkIKEv2 (args, targets, vpns)
	
	if not len(vpns.keys()):
		print "\033[93m[*]\033[0m No IKE service was found. Bye ;)"
		exit(0)
	
	# 2. Fingerprint by checking VIDs and by analysing the service responses
	fingerprintVID (args, vpns)
	fingerprintShowbackoff (args, vpns)
	
	
	# 3. Ciphers
	checkEncriptionAlgs (args, vpns)
	
	
	# 4. Aggressive Mode
	checkAggressive (args, vpns)
	
	
	# 5. Enumerate client IDs
	enumerateGroupID (args, vpns)
	
	
	# . Parse the results
	parseResults (args, vpns)

	
	printMessage ( "iker finished at %s" % strftime("%a, %d %b %Y %H:%M:%S +0000", localtime()), args.output )


if  __name__ =='__main__':
	main()



# Verde: \033[92m[*]\033[0m 
# Rojo: \033[91m[*]\033[0m 
# Amarillo: \033[93m[*]\033[0m 


#{ IP : {
	#"vid" : ["XXXX", ...]
	#"showbackoff
	#"handshake" : ""
	#"transforms" : ["", "", ...]
	#}

#}



