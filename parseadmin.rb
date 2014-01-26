#!/usr/bin/ruby -w
require 'nokogiri'
 
# check to make sure an argument was given
if ARGV.size != 1 then
  puts "[-] Usage: ./parseadmin.rb <nmap.xml>"
  puts ""
  puts "Run Nmap smb-enum Nmap script to generate outfile:"
  puts "nmap -p 445 --open --script=smb-enum-shares.nse --script-args=smbuser=<USERNAME>,smbpass=<USERPASS>,smbdomain=<DOMAIN>" 
  puts "" 
  exit
end
 
xml = Nokogiri::XML.parse(open ARGV[0])
 
# diplay which ip address our credentials have local admin on
xml.css('nmaprun host').each do |host|
  begin
    target_address = host.css('address').first['addr']
    target_hostnames = host.css('hostname').first['name']
    target_scripts = host.css('hostscript script')
  rescue Exception => e
    puts "[-] Error On: #{target_address}t#{target_hostnames}"
    next
  end
 
  target_scripts.each do |script|
    puts "[+] Local Admin on:  #{target_address}t#{target_hostnames}" if script['output'] =~ /WRITE/
  end
end
