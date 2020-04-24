#!/bin/bash
# check-smb-signing.sh (v2.0)
# v1.1 - 10/26/2017 by Ted R (http://github.com/actuated)
# v2.0 - 10/30/2017
# Script to run and parse SMB message signing results using Nmap's smb-security-mode.nse or RunFinger.py
# 11/01/2017 - Test of different options and conditions
# 11/03/2017 - Added support for RunFinger.py stdout input file parsing
varDateCreated="10/30/2017"
varDateLastMod="11/03/2017"

# Set location for RunFinger.py
varRunFingerLocation="/usr/share/responder/tools/RunFinger.py"

varYMDHM=$(date +%F-%H-%M)
varHM=$(date +%H-%M)
varOutDir="csmbs-$varYMDHM"
varOutScan="csmbs-scan-$varHM.txt"
varOutParsed="csmbs-parsed-$varHM.txt"
varOutCount="csmbs-count-$varHM.txt"
varTempAddrs="csmbs-temp-addrs-$varHM.txt"
varTool="N"
varCountTool=0
varInMode="N"
varCountInMode=0
varHostDiscovery="N"

function fnUsage {
  echo
  echo "======================================[ about ]======================================"
  echo
  echo "Run a scan for SMB signing mode and/or parse a file of results into a count of hosts"
  echo "and split files listing hosts with each signing mode value."
  echo
  echo "Specify Nmap's smb-security-mode.nse or lgandx's RunFinger.py. Specify a file listing"
  echo "target hosts, an address or address range, or a file containing results from either."
  echo
  echo "Created $varDateCreated, last modified $varDateLastMod."
  echo
  echo "======================================[ usage ]======================================"
  echo
  echo "./check-smb-signing.sh [tool] [input options] [--out-dir [dir]] [--host-discovery]"
  echo
  echo "Tool Parameter (must specify one):"
  echo "--finger               Use lgandx's RunFinger.py to check SMB signing."
  echo "--nmap                 Use Nmap's smb-security-mode.nse to check SMB signing."
  echo
  echo "Input Options (must specify one):"
  echo "-a [address/range]     Specify an address or address range to scan."
  echo "-f [file]              Specify a file containing addresses to scan."
  echo "-r [file]              Specify a file containing stdout Nmap smb-security-mode.nse"
  echo "                       results or RunFinger.py output to parse (no scan is run)."
  echo
  echo "Note: -a and -f inputs will run through an Nmap list scan (-sL) to create a list of"
  echo "target hosts from any Nmap-friendly range input before the NSE or RunFinger.py are"
  echo "run against that resulting list of target hosts."
  echo
  echo "--finger-path [path]   When using --finger, specify the location of RunFinger.py"
  echo "                       (including the filename). You can also change the value for"
  echo "                       the varRunFingerLocation variable near the beginning of the"
  echo "                       script."
  echo
  echo "--out-dir [path]       Optionally specify a directory for output files (see below)."
  echo "                       The default is 'csmbs-YMDHM/'."
  echo
  echo "--host-discovery       Optionally perform an Nmap host discovery scan (-sn) against"
  echo "                       -a or -f target hosts before running the NSE or RunFinger.py."
  echo
  echo "===================================[ file output ]==================================="
  echo
  echo "csmbs-count-HH-MM.txt       Output file with the color counts created by the script."
  echo "csmbs-parsed-HH-MM.txt      Output file with '[host]   [SMB signing value]' results."
  echo "csmbs-scan-HH-MM.txt        RunFinger.py or Nmap smb-security-mode.nse scan results."
  echo "                            Not included when -r is used to parse your own results."
  echo "hosts-signing-[value].txt   A list of hosts for each SMB signing value (true or false"
  echo "                            for RunFinger.py and disabled, supported, or required for"
  echo "                            the NSE. Only created when there are applicable hosts."
  echo
  echo "=======================================[ fin ]======================================="
  echo
  exit
}

function fnScan {
  
  # Convert host lists and address ranges to a list of individual hosts
  # This lets you specify Nmap-style ranges for RunFinger instead of just /24s or individual IPs
  # This also ensures that even hostname inputs are converted to IPs
  if [ "$varInMode" = "File" ]; then
    nmap -iL "$varTarget" -sL -n -oG - | awk '/Host/{print $2}' | sort -V > "$varOutDir/$varTempAddrs"
  elif [ "$varInMode" = "Address" ]; then
    nmap "$varTarget" -sL -n -oG - | awk '/Host/{print $2}' | sort -V > "$varOutDir/$varTempAddrs"
  fi

  # Optionally use Nmap to do host discovery before running the NSE or RunFinger
  if [ "$varHostDiscovery" = "Y" ]; then
    echo
    varTimeNow=$(date +%H:%M)
    varCountScanHosts=$(wc -l "$varOutDir/$varTempAddrs" | awk '{print $1}')
    echo "$varTimeNow - Starting host discovery for $varCountScanHosts hosts."
    mv "$varOutDir/$varTempAddrs" "$varOutDir/csmbs-temp-before-host-discovery.txt"
    nmap -iL "$varOutDir/csmbs-temp-before-host-discovery.txt" -sn -n -oG - | awk '/Up/{print $2}' | sort -V > "$varOutDir/$varTempAddrs"
    rm "$varOutDir/csmbs-temp-before-host-discovery.txt"
    varTimeNow=$(date +%H:%M)
    varCountScanHosts=$(wc -l "$varOutDir/$varTempAddrs" | awk '{print $1}')
    echo "$varTimeNow - Host discovery done with $varCountScanHosts hosts."
  fi

  # Run Nmap or RunFinger against target addresses
  echo
  varTimeNow=$(date +%H:%M)
  varCountScanHosts=$(wc -l "$varOutDir/$varTempAddrs" | awk '{print $1}')
  echo "$varTimeNow - Starting $varTool for $varCountScanHosts hosts."
  if [ "$varTool" = "Nmap" ]; then
    nmap -iL "$varOutDir/$varTempAddrs" -sS -Pn -n -p 445 --open --script smb-security-mode.nse > "$varOutDir/$varOutScan"
  elif [ "$varTool" = "RunFinger" ]; then
    cat "$varOutDir/$varTempAddrs" | xargs -I % python "$varRunFingerLocation" -g -i % > "$varOutDir/$varOutScan"
  fi
  varTimeNow=$(date +%H:%M)
  echo "$varTimeNow - $varTool completed (see $varOutScan)."
  
  if [ -f "$varOutDir/$varTempAddrs" ]; then rm "$varOutDir/$varTempAddrs"; fi

}

function fnParse {

  # Select scan results to parse based on input mode
  if [ "$varInMode" = "Results" ]; then
    varScanResults="$varTarget"
  else
    varScanResults="$varOutDir/$varOutScan"
  fi

  if [ "$varTool" = "Nmap" ]; then
    # Make sure scan results exist
    varCheckResults=$(grep message_signing "$varScanResults" --color=never)
    if [ "$varCheckResults" = "" ]; then
      echo
      echo "Parsing Error: $varTarget contains no 'message_signing' lines."
      echo
      echo "=======================================[ fin ]======================================="
      echo
      exit
    else
      # Create 'host   result' parsed file for Nmap results
      echo > "$varOutDir/$varOutParsed"
      echo "=================[ check-smb-signing.sh - Ted R (github: actuated) ]=================" >> "$varOutDir/$varOutParsed"
      echo  >> "$varOutDir/$varOutParsed"
      while read varThisLine; do
        varCheckForScanReport=$(echo "$varThisLine" | grep "Nmap scan report for" --color=never)
        if [ "$varCheckForScanReport" != "" ]; then
          varLastHost=$(echo "$varThisLine" | awk '{print $NF}' | tr -d '()')
        fi
        varCheckForVulnState=$(echo "$varThisLine" | grep "message_signing" --color=never)
        if [ "$varCheckForVulnState" != "" ]; then
          varStatus=$(echo "$varThisLine" | awk '{print $2, $3}')
          echo -e "$varLastHost\t$varStatus" >> "$varOutDir/$varOutParsed"
        fi
      done < "$varScanResults"
      echo  >> "$varOutDir/$varOutParsed"
      echo "=======================================[ fin ]=======================================" >> "$varOutDir/$varOutParsed"
      echo  >> "$varOutDir/$varOutParsed"
    fi
  elif [ "$varTool" = "RunFinger" ]; then
    # See if scan results are grepable, stdout, or do not exist
    varCheckResultsGrep=$(grep ", Signing:" "$varScanResults" --color=never)
    varCheckResultsStdOut=$(grep Retrieving "$varScanResults" --color=never)
    if [ "$varCheckResultsGrep" != "" ]; then
      # Create 'host   result' parsed file for grepable RunFinger results
      echo > "$varOutDir/$varOutParsed"
      echo "=================[ check-smb-signing.sh - Ted R (github: actuated) ]=================" >> "$varOutDir/$varOutParsed"
      echo  >> "$varOutDir/$varOutParsed"
      awk -F, '{print $1 "\t" $4}' "$varScanResults" | tr -d [\' >> "$varOutDir/$varOutParsed"
      echo  >> "$varOutDir/$varOutParsed"
      echo "=======================================[ fin ]=======================================" >> "$varOutDir/$varOutParsed"
      echo  >> "$varOutDir/$varOutParsed"
    elif [ "$varCheckResultsStdOut" != "" ]; then
      # Create 'host   result' parsed file for stdout RunFinger results
      echo > "$varOutDir/$varOutParsed"
      echo "=================[ check-smb-signing.sh - Ted R (github: actuated) ]=================" >> "$varOutDir/$varOutParsed"
      echo  >> "$varOutDir/$varOutParsed"
      while read varThisLine; do
        varCheckForScanReport=$(echo "$varThisLine" | grep Retrieving --color=never)
        if [ "$varCheckForScanReport" != "" ]; then
          varLastHost=$(echo "$varThisLine" | awk '{print $4}' | sed 's/\.\.\.//g')
        fi
        varCheckForVulnState=$(echo "$varThisLine" | grep "SMB signing" --color=never)
        if [ "$varCheckForVulnState" != "" ]; then
          varStatus=$(echo "$varThisLine" | awk '{print "Signing:" $NF}')
          echo -e "$varLastHost\t$varStatus" >> "$varOutDir/$varOutParsed"
        fi
      done < "$varScanResults"
      echo  >> "$varOutDir/$varOutParsed"
      echo "=======================================[ fin ]=======================================" >> "$varOutDir/$varOutParsed"
      echo  >> "$varOutDir/$varOutParsed"            
    elif [ "$varCheckResultsGrep" = "" ] && [ "$varCheckResultsStdOut" = "" ]; then
      echo
      echo "Parsing Error: $varTarget contains no 'Signing:' lines."
      echo
      echo "=======================================[ fin ]======================================="
      echo
      exit
    fi
  fi
}

function fnCount {

  if [ "$varTool" = "Nmap" ]; then

    # Create totals
    varTotalHosts=$(grep message_signing "$varOutDir/$varOutParsed" | wc -l )
    varSigningRequired=$(grep required "$varOutDir/$varOutParsed" | wc -l )
    varSigningSupported=$(grep supported "$varOutDir/$varOutParsed" | wc -l )
    varSigningDisabled=$(grep disabled "$varOutDir/$varOutParsed" | wc -l)
    varPercentRequired=$(awk "BEGIN {print $varSigningRequired*100/$varTotalHosts}" | cut -c1-4)%
    varPercentSupported=$(awk "BEGIN {print $varSigningSupported*100/$varTotalHosts}" | cut -c1-4)%
    varPercentDisabled=$(awk "BEGIN {print $varSigningDisabled*100/$varTotalHosts}" | cut -c1-4)%

    # Display totals
    echo
    echo -e "\033[1;37m Total SMB Hosts: \t\t $varTotalHosts \e[0m"
    echo
    echo -e "\033[33;32m Signing Required: \t\t $varSigningRequired ($varPercentRequired) \e[0m"
    echo -e "\033[33;33m Supported, not Required: \t $varSigningSupported ($varPercentSupported) \e[0m"
    echo -e "\033[33;31m Signing Disabled: \t\t $varSigningDisabled ($varPercentDisabled) \e[0m"

    # Create host lists for each result type
    if [ "$varSigningDisabled" -gt "0" ]; then
      grep disabled "$varOutDir/$varOutParsed" | awk '{print $1}' | sort -V > "$varOutDir/hosts-signing-disabled.txt"
    fi
    if [ "$varSigningSupported" -gt "0" ]; then
      grep supported "$varOutDir/$varOutParsed" | awk '{print $1}' | sort -V > "$varOutDir/hosts-signing-supported.txt"
    fi
    if [ "$varSigningRequired" -gt "0" ]; then
      grep required "$varOutDir/$varOutParsed" | awk '{print $1}' | sort -V > "$varOutDir/hosts-signing-required.txt"
    fi

  elif [ "$varTool" = "RunFinger" ]; then

    # Create totals
    varTotalHosts=$(grep Signing: "$varOutDir/$varOutParsed" | wc -l )
    varSigningFalse=$(grep Signing:False "$varOutDir/$varOutParsed" | wc -l )
    varSigningTrue=$(grep Signing:True "$varOutDir/$varOutParsed" | wc -l )
    varPercentFalse=$(awk "BEGIN {print $varSigningFalse*100/$varTotalHosts}" | cut -c1-4)%
    varPercentTrue=$(awk "BEGIN {print $varSigningTrue*100/$varTotalHosts}" | cut -c1-4)%

    # Display totals
    echo
    echo -e "\033[1;37m Total SMB Hosts: \t $varTotalHosts \e[0m"
    echo
    echo -e "\033[33;32m Signing True: \t\t $varSigningTrue ($varPercentTrue) \e[0m"
    echo -e "\033[33;31m Signing False: \t $varSigningFalse ($varPercentFalse) \e[0m"

    # Create host lists for each result type
    if [ "$varSigningTrue" -gt "0" ]; then
      grep Signing:True "$varOutDir/$varOutParsed" | awk '{print $1}' | sort -V > "$varOutDir/hosts-signing-true.txt"
    fi
    if [ "$varSigningFalse" -gt "0" ]; then
      grep Signing:False "$varOutDir/$varOutParsed" | awk '{print $1}' | sort -V > "$varOutDir/hosts-signing-false.txt"
    fi

  fi

}

function fnCheckOptions {

  # Make sure only one tool specified
  if [ $varCountTool = 0 ]; then
    echo
    echo "Error: No tool (--nmap or --finger) specified."
    fnUsage
  elif [ $varCountTool -gt 1 ]; then
    echo
    echo "Error: Specify only --nmap or --finger."
    fnUsage
  fi

  # Check RunFinger location if being used
  if [ "$varTool" = "RunFinger" ] && [ ! -f "$varRunFingerLocation" ]; then
    echo
    echo "Error: $varRunFingerLocation does not exist."
    echo "Use --finger-path or modify varRunFingerLocation in script to specify the file"
    echo "location of RunFinger.py, including the file name."
    echo
    echo "Get Tools/RunFinger.py from https://github.com/lgandx/responder."
    fnUsage
  fi

  # Make sure only one input mode specified
  if [ $varCountInMode = 0 ]; then
    echo
    echo "Error: No input mode (-f, -a, -r) specified."
    fnUsage
  elif [ $varCountInMode -gt 1 ]; then
    echo
    echo "Error: Specify only one input mode (-f, -a, or -r)."
    fnUsage
  fi

  # Check file input
  if [ "$varInMode" = "File" ] && [ ! -f "$varTarget" ]; then
    echo
    echo "Error: $varTarget does not exist as a file."
    fnUsage
  fi

  # Check address input
  if [ "$varInMode" = "Address" ]; then
    varCheckAddress=$(echo "$varTarget" | grep [[:digit:]].[[:digit:]].[[:digit:]].[[:digit:]] --color=never)
    if [ "$varCheckAddress" = "" ]; then
      echo
      echo "Error: '$varTarget' does not appear to be an IP address or range."
    fi
  fi

  # See if output directory exists
  if [ -d "$varOutDir" ]; then
    echo
    echo "Note: $varOutDir/ exists. Prior output files may be overwritten."
    read -p "Press Enter to continue..."
  else
    mkdir "$varOutDir"
    if [ ! -d "$varOutDir" ]; then
      echo
      echo "Error: Could not create output directory '$varOutDir'."
      echo
      echo "=======================================[ fin ]======================================="
      echo
      exit
    fi
  fi
}

echo
echo "=================[ check-smb-signing.sh - Ted R (github: actuated) ]================="

  # Read options
  while [ "$1" != "" ]; do
    case "$1" in
      --nmap )
        varTool="Nmap"
        let varCountTool=varCountTool+1
        ;;
      --finger )
        varTool="RunFinger"
        let varCountTool=varCountTool+1
        ;;
      -f )
        varInMode="File"
        let varCountInMode=varCountInMode+1
        shift
        varTarget="$1"
        ;;
      -a )
        varInMode="Address"
        let varCountInMode=varCountInMode+1
        shift
        varTarget="$1"
        ;;
      -r )
        varInMode="Results"
        let varCountInMode=varCountInMode+1
        shift
        varTarget="$1"
        ;;
      --finger-path )
        shift
        varRunFingerLocation="$1"
        ;;
      --out-dir )
        shift
        varOutDir="$1"
        ;;
      --host-discovery )
        varHostDiscovery="Y"
        ;;
      -h )
        fnUsage
        ;;
      * )
        echo
        echo "Error: Unrecognized argument/option."
        fnUsage
        ;;
    esac
    shift
  done

fnCheckOptions

if [ "$varInMode" != "Results" ]; then fnScan; fi

fnParse

echo > "$varOutDir/$varOutCount"
echo "=================[ check-smb-signing.sh - Ted R (github: actuated) ]=================" >> "$varOutDir/$varOutCount"
fnCount | tee -a "$varOutDir/$varOutCount"
echo | tee -a "$varOutDir/$varOutCount"
echo "=======================================[ fin ]=======================================" | tee -a "$varOutDir/$varOutCount"
echo | tee -a "$varOutDir/$varOutCount"



