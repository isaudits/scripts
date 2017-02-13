#!/bin/bash
 
#Built for Kali
#
# This tool will use rcrack to perform the full cracking process of a Half LM Hash.
#
#
# Usage: ./hlmcrack.sh hlmhashes.txt
#  
# By: Leon Teale (RandomStorm)
#
 
#Set path to your half lm tables
hlmtable=/opt/tables/rcracki_mt/Halflm_tables_all-space
 
 
 
#Check usage
if [ -z "$1" ];
then
echo "Usage: ./hlmcrack.sh john_netntlm.txt"
 
else
 
for line in `cat $1 | sort -u`; do
 
echo "$line" > /tmp/newhash.txt
hash="$line"
username="`echo $line | cut -d : -f 1`"
seedhash="`echo $line | cut -d : -f 4 | sed 's/\(.\{16\}\).*/\1/'`"
echo $hash
echo $username
echo $seedhash
 
#Get the seed (the first 16 digits of the hash)
/usr/bin/rcracki_mt -h $seedhash $hlmtable > /tmp/seed.tmp
 
seed=`cat /tmp/seed.tmp | grep "plaintext of" | awk {'print ($NF)'}`
 
#Crack the remaining hash
perl /usr/share/metasploit-framework/data/john/run.linux.x64.mmx/netntlm.pl --seed $seed --file /tmp/newhash.txt 1> /dev/null
perl /usr/share/metasploit-framework/data/john/run.linux.x64.mmx/netntlm.pl --file /tmp/newhash.txt | grep "($username)" 2> /dev/null >> /tmp/hlmcrack.txt
 
done
fi
 
#Printed Output
clear
echo "#################################################################################"
echo "Half LM cracked:  cracked `cat /tmp/hlmcrack.txt | wc -l`\\`cat $1 | wc -l`"
echo ""
cat /tmp/hlmcrack.txt
echo ""
echo "#################################################################################"
rm /tmp/hlmcrack.txt
rm /tmp/newhash.txt
rm /tmp/seed.tmp