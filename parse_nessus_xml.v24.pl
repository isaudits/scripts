#!/opt/local/bin/perl

use strict;
use XML::TreePP;
use Data::Dumper;
use Math::Round;
use Excel::Writer::XLSX;
use Data::Table;
use Excel::Writer::XLSX::Chart;
use Getopt::Std;
#use Devel::Size qw(size total_size);   #############  New module

print "";
## Copyright (C) 2016  Cody Dumont
##
## This program is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License
## as published by the Free Software Foundation; either version 2
## of the License, or (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
## This is a program to parse a series of Nessus XMLv2
## files into a XLSX file.  The data from the XML file is placed into a series
## of tabs to for easier review and reporting.  New features with this edition
## are better reporting of policy plugin families, user account reporting,
## summary graphs, and a home page with summary data.  For more information
## and questions please contact Cody Dumont cody@melcara.com
##
## Version 0.24

our %recast_plugin;
our (@installedSoftware,@portScanner,@vuln_entries,@host_scan_data,@WinWirelessSSID,@cpe_data,@PCIDSS,@ADUsers,@ScanInfo,@MS_Process_Info);
our (@WinUserData,@WinUsers,@WinGuestUserData,@PasswordPolicyData,@WirelessAccessPointDetection,@DeviceType,@EnumLocalGrp);
our $highvuln_cnt = 0;
our $medvuln_cnt = 0;
our $lowvuln_cnt = 0;
our $nonevuln_cnt = 0;
our $PolicySummaryReport_worksheet;
our $PolicySummaryReport_cnt;
our $center_format;
our $center_border6_format;
our $cell_format;
our $wrap_text_format;
our $workbook;
my $is_domain_controller_users_checked = 0;
our %complaince;
our %compliance_summary;
our %audit_result_type;
our %vulnerability_data;
our %ip_vuln_data;
our %ms_process_cnt;
our $home_url;
our $url_format;
my @targets;
my $target_cnt;
our $ip_add_regex = '(25[0-5]|[2][0-4][0-9]|1[0-9]{2}|[\d][\d]|[\d])(\.(25[0-5]|[2][0-4][0-9]|1[0-9]{2}|[\d][\d]|[\d])){3}';
my $dir;
my $target_file;
my @xml_files;
our %cvss_score;
our $port_scan_plugin = '(10335)|(34277)|(11219)|(14272)|(34220)';
our $installed_software_plugin = '(20811)|(58452)|(22869)';
our %total_discovered;
our %vuln_totals;
our @host_data;
my @PolicyCompliance;
my @policy_data;

my $new_stuff = '
These are the new features with version 24

1.  Fix regex \Q\E line est 1477,1484 v22
2.  Removing plugin 33929 from High Vulns calculation
3.  Removed Compliance from being part of High Vuln Calculation
4.  Version 23 Skipped
5.  reordered vuln data processing to not use as much memory.
6.  
7. 
8.  
9.  
';

print $new_stuff;
sleep 2;

#####################  get arguments from the command
my $help_msg = '
NAME
    parse_nessus_xml.v24.pl -- parse nessus v2 XML files into an XLSX file
    
SYNOPSIS
    perl parse_nessus_xml.v24.pl [-vVhH] [-f file] [-d directory] [-r recast_file optional ]

DESCRIPTION
    Nessus Parser v0.24 - This is a program to parse a series of Nessus XMLv2
    files into a XLSX file.  The data from the XML file is placed into a series
    of tabs to for easier review and reporting.  New features with this edition
    are better reporting of policy plugin families, user account reporting,
    summary graphs, and a home page with summary data.  For more information
    and questions please contact Cody Dumont cody@melcara.com
    
    The Nessus parser requires some additional modules, they are:
    o	XML::TreePP
    o	Data::Dumper
    o	Math::Round
    o	Excel::Writer::XLSX
    o	Data::Table
    o	Excel::Writer::XLSX::Chart
    o	Getopt::Std

    The options are as follows:
    -o      Changes the filename prefix.  The default prefix is "nessus_report".
            A time stamp is appended onto the prefix.  An exmaple of the default
            file name is nessus_report_20130409162908.xlsx.  if the "-o foobar" is
            passed, then the file name will be foobar_20130409162908.xlsx
    
    -d      The target directory where the Nessus V2 XML files are located.
            This option will search the target directory files that end with
            XML, xml, or nessus extentions.  Each file found will be check for
            Nessus V2 XML format.  Each Nessus V2 XML file will be parsed and
            will be stored into an XLSX file.  This option should not be used
            with any other option.

    -f      The target file is a method to call a single file for parsing.
            With this method the XLSX file will be stored in the same folder
            as the XML.  Please note if the path to file has a "SPACE" use
            double quotes around the file path and/or name.

    -r      The Recast option is a feature request from user KurtW.  Kurt wanted
            to be able to change the reported value of Nessus Plugin ID.  While
            this is not recommended in many cases, in some instances the change
            may provide the Nessus user with more accurate report.
            To use this feature create a CSV file with three fields.
            
            Field 1:  Nessus Plugin ID
            Field 2:  Nessus-assigned Severity
            Field 3:  Recasted (User-assigned) Severity
            
            Examples
            
            # Recast vulnerability SSL Certificate Cannot Be Trusted (Plugin ID 51192) from Medium to Critical
            51192,2,4
            
            # Recast vulnerability MySQL 5.1 < 5.1.63 Multiple Vulnerabilities (Plugin ID 59448) from High to Low
            59448,3,1
            
            # Recast vulnerability MS12-067: Vulnerabilities in FAST Search Server 2010 for Sharepoint RCE from High to Critical
            62462,3,4
            
            The file would contain 3 lines.
            51192,2,4
            59448,3,1
            62462,3,4
            
            The command used would be passed the -r recast.txt.  See examples listed below.

    -v      Print this help message.

    -h      Print this help message.
    
    EXAMPLES
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -v
            
            This command will print this help message.
        
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -h
            
            This command will print this help message.
        
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -d /foo/bar
            
            This command will seearch the direcoty specified by the "-d" option
            for Nessus XML v2 files and parse the files found.
        
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -f /foo/bar/scan1.nessus
                -----  or -----
                perl /path/to/script/parse_nessus_xml.v24.pl -f /foo/bar/scan1.nessus.xml
            
            This command will seearch the direcoty specified by the "-d" option
            for Nessus XML v2 files and parse the files found.
            
        The command:
                perl /path/to/script/parse_nessus_xml.v24.pl -f /foo/bar/scan1.nessus -r /path/to/script/recast.txt
                
';

my $version = $ARGV[0];
my %opt;
getopt('dfro', \%opt);

if($version =~ /-(v|V|h|H)/){
    print $help_msg;exit;
}
elsif($opt{"d"} && $opt{"f"}){
    print "Please only use a file or directory as a command line argument.\n\n";
    print $help_msg;exit;
}
elsif($opt{"d"}){
    $dir = $opt{"d"};
    print "The target directory is \"$dir\"\.\n";
    opendir DIR, $dir;
    my @files = readdir(DIR);
    closedir DIR;
    my @xml = grep {$_ =~ /((xml)|(XML)|(nessus))$/} @files;
    #@xml_files = grep {$_ !~ /^\./} @xml_files;
    my @verified;
    my $eol_marker = $/;
    undef $/;
    
    foreach (@xml){
        my $f = "$dir/$_";
        open FILE, $f;
        my $tmp_data = <FILE>;
        close FILE;
        if($tmp_data =~ /(NessusClientData_v2)/m){print "File $_ is a Valid Nessus Ver2 format and will be parsed.\n\n";push @verified,$f}
        else{print "This file \"$_\" is not using the Nessus version 2 format, and will NOT be parsed!!!\n\n";}
    }
    # end of foreach (@xml)
    $/ = $eol_marker;
    @xml_files = @verified;
}
elsif($opt{"f"}){
    $target_file = $opt{"f"};
    print "The target file is \"$target_file\"\.\n";
    my $eol_marker = $/;
    undef $/;
    open FILE, $target_file;
    my $tmp_data = <FILE>;
    close FILE;
    if($tmp_data =~ /(NessusClientData_v2)/m){
        print "File $target_file is a Valid Nessus Ver2 format and will be parsed.\n\n";
        my @dirs = split /\\|\//,$target_file;
        pop @dirs;
        if(!@dirs){push @dirs, "."}
        $dir = join "/", @dirs;
        push @xml_files, $target_file;
        
        print "";
    }
    else{print "This file \"$target_file\" is not using the Nessus version 2 format, and will NOT be parsed!!!\n\n";exit;}
    $/ = $eol_marker;
}
else{
    print $help_msg;exit;
}

if($opt{"r"}){
    my $recast_file = $opt{"r"};
    print "The recast option is selected, the recast definition file is \"$recast_file\"\.\nPlease note all the following Plugin ID's will have thier severity changed accordingly.\n\n";
    open FILE, $recast_file or die "Can't open the $recast_file file\n";
    my @tmp_data = <FILE>;
    close FILE;
    chomp @tmp_data;
    print "PLUGIN ID\tOLD SEV\tNEW SEV\n";
    foreach my $p (@tmp_data){
        my @t = split /\,/,$p;
        if($t[3]){print "There is a error in your RECAST file, please review the help message using the -h option.\n";exit;}
        print "$t[0]\t\t$t[1]\t$t[2]\n";
        $recast_plugin{$t[0]}->{old} = $t[1];
        $recast_plugin{$t[0]}->{new} = $t[2];
    }
}


##################   end command arguments

######  Code contributed by Whinston Antion <Whinston.Antion AT mail.wvu.edu>
my $random_number = rand();
my $now_string = localtime;
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
my $report_prefix = "nessus_report";
if($opt{"o"}){$report_prefix = $opt{"o"}}
my $report_file = sprintf("%4d%02d%02d%02d%02d%02d",($year + 1900),($mon+1),$mday,$hour,$min,$sec);
######  end contribution

print "
################################################################################
                            NESSUS PARSER V0.24
################################################################################
";

##############################  START SUBROUTINES

sub vulnerability_plugin_worksheet {
    my $vuln_type = $_[0];
    my $tmp_worksheet = $_[1];
    my $vuln_type_ctr = 2;
    $tmp_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $tmp_worksheet->keep_leading_zeros();
    $tmp_worksheet->write(1, 0, 'File',$center_border6_format);
    $tmp_worksheet->write(1, 1, 'plugin Family',$center_border6_format);
    $tmp_worksheet->write(1, 2, 'plugin id',$center_border6_format);
    $tmp_worksheet->write(1, 3, 'plugin Name',$center_border6_format);
    $tmp_worksheet->write(1, 4, 'count',$center_border6_format);
    $tmp_worksheet->write(1, 5, 'Bid',$center_border6_format);
    $tmp_worksheet->write(1, 6, 'CVE',$center_border6_format);
    $tmp_worksheet->write(1, 7, 'OSVDB',$center_border6_format);
    $tmp_worksheet->write(1, 8, 'CVSS Vector',$center_border6_format);
    $tmp_worksheet->write(1, 9, 'CVSS Base Score',$center_border6_format);
    $tmp_worksheet->write(1, 10, 'CVSS Temporal Score',$center_border6_format);
    $tmp_worksheet->write(1, 11, 'Solution',$center_border6_format);
    $tmp_worksheet->write(1, 12, 'Description',$center_border6_format);
    $tmp_worksheet->write(1, 13, 'Exploitability Ease',$center_border6_format);
    $tmp_worksheet->write(1, 14, 'Exploit Available',$center_border6_format);
    $tmp_worksheet->write(1, 15, 'Exploit Framework Canvas',$center_border6_format);
    $tmp_worksheet->write(1, 16, 'Exploit Framework Metasploit',$center_border6_format);
    $tmp_worksheet->write(1, 17, 'Exploit Framework Core',$center_border6_format);
    $tmp_worksheet->write(1, 18, 'Metasploit Name',$center_border6_format);
    $tmp_worksheet->write(1, 19, 'Canvas Package',$center_border6_format);
    $tmp_worksheet->write(1, 20, 'Solution',$center_border6_format);
    $tmp_worksheet->write(1, 21, 'Synopsis',$center_border6_format);
    $tmp_worksheet->write(1, 22, 'plugin_publication_date',$center_border6_format);
    $tmp_worksheet->write(1, 23, 'plugin_modification_date',$center_border6_format);
    $tmp_worksheet->write(1, 24, 'patch_publication_date',$center_border6_format);
    $tmp_worksheet->write(1, 25, 'vuln_publication_date',$center_border6_format);
    
    $tmp_worksheet->freeze_panes('C3');
    $tmp_worksheet->autofilter('A2:Z2');
    $tmp_worksheet->set_column('A:A', 20);
    $tmp_worksheet->set_column('B:B', 25);
    $tmp_worksheet->set_column('C:C', 10);
    $tmp_worksheet->set_column('D:D', 35);
    $tmp_worksheet->set_column('E:H', 10);
    $tmp_worksheet->set_column('I:R', 35);
    $tmp_worksheet->set_column('S:S', 60);
    $tmp_worksheet->set_column('T:T', 60);
    $tmp_worksheet->set_column('U:U', 60);
    $tmp_worksheet->set_column('V:V', 60);
    $tmp_worksheet->set_column('W:Z', 20);
    foreach (@{$vulnerability_data{$vuln_type}}){
        my @tmp = split /\,/, $_;
        $tmp_worksheet->write($vuln_type_ctr, 0, $tmp[4],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 1, $tmp[5],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 2, $tmp[0],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 3, $tmp[3],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 4, $tmp[2],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 5, $tmp[6],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 6, $tmp[7],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 7, $tmp[8],$wrap_text_format);
        $tmp_worksheet->write($vuln_type_ctr, 8, $tmp[19],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 9, $tmp[18],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 10, $tmp[20],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 11, $tmp[9],$wrap_text_format);
        $tmp_worksheet->write($vuln_type_ctr, 12, $tmp[10],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 13, $tmp[11],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 14, $tmp[12],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 15, $tmp[13],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 16, $tmp[14],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 17, $tmp[15],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 18, $tmp[16],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 19, $tmp[17],$wrap_text_format);
        $tmp_worksheet->write($vuln_type_ctr, 20, $tmp[21],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 21, $tmp[22],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 22, $tmp[23],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 23, $tmp[24],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 24, $tmp[25],$cell_format);
        $tmp_worksheet->write($vuln_type_ctr, 25, $tmp[26],$cell_format);
        ++$vuln_type_ctr;
    }
    # end foreach (@criticalvuln)
    return $tmp_worksheet;
}
# end of sub vulnerability_plugin_worksheet

sub compliance_worksheet {
    my $complaince_type = $_[0];

    my $complaince_name = $complaince_type;
    $complaince_name =~ s/Compliance Checks//;
    $complaince_name =~ s/\s//g;
    $complaince_name =~ s/[[:punct:]]//g;

    my $complaince_name1 = substr ($complaince_name, 0, 23);
    $complaince_name = "$complaince_name1 Policy";
    my $Compliance_ctr = 2;
    my $Compliance_worksheet = $workbook->add_worksheet($complaince_name);
    $Compliance_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $Compliance_worksheet->keep_leading_zeros();
    $Compliance_worksheet->write(1, 0, 'File',$center_border6_format);
    $Compliance_worksheet->write(1, 1, 'IP Address',$center_border6_format);
    $Compliance_worksheet->write(1, 2, 'FQDN',$center_border6_format);
    $Compliance_worksheet->write(1, 3, 'PluginID',$center_border6_format);
    #$Compliance_worksheet->write(1, 4, 'protocol',$center_border6_format);
    $Compliance_worksheet->write(1, 4, 'Severity',$center_border6_format);
    #$Compliance_worksheet->write(1, 5, 'pluginFamily',$center_border6_format);
    $Compliance_worksheet->write(1, 5, 'Audit File',$center_border6_format);
    #$Compliance_worksheet->write(1, 6, 'Policy Type',$center_border6_format);
    $Compliance_worksheet->write(1, 6, 'Policy Setting',$center_border6_format);
    $Compliance_worksheet->write(1, 7, 'Result',$center_border6_format);
    $Compliance_worksheet->write(1, 8, 'System Value/Error Messages',$center_border6_format);
    $Compliance_worksheet->write(1, 9, 'Compliance Requirement',$center_border6_format);
    $Compliance_worksheet->write(1, 10, 'Description of Requirement',$center_border6_format);

    # JB Init Changes
    # add column for solution
    $Compliance_worksheet->write(1, 11, 'Solution',$center_border6_format);
    $Compliance_worksheet->write(1, 12, 'Authority Document',$center_border6_format);
    $Compliance_worksheet->write(1, 13, 'Cross References',$center_border6_format);
    ## End Init Changes

    $Compliance_worksheet->freeze_panes('C3');
    $Compliance_worksheet->autofilter('A2:N2');
    $Compliance_worksheet->set_column('A:N', 20);

    foreach (@{$complaince{$complaince_type}}){
        my @tmp;
        my $remote_value;
        my @compliance_check_name = split / - /,$_->{vuln}->{'cm:compliance-check-name'};
        #foreach my $k (keys %{$_->{vuln}}){$_->{vuln}->{"$k"} =~ s/\n/\|/g;}
        #if ($compliance_check_name[1] eq "") {
        #    my @tmp = split /: /,$_->{vuln}->{'cm:compliance-check-name'};
        #    $compliance_check_name[0] = "$tmp[0] $tmp[1]";
        #    $compliance_check_name[1] = "$tmp[2]";
        #}
        my $compliance_value;
        if ($_->{vuln}->{description} =~ /(?<=Remote value:).+?(?=^Policy value:)/ism){$remote_value = substr($_->{vuln}->{description},$-[0],$+[0]-$-[0]);}
        if ($_->{vuln}->{description} =~ /(?<=Policy value:).+?\Z/ism){$compliance_value = substr($_->{vuln}->{description},$-[0],$+[0]-$-[0]);}
        $remote_value =~ s/ {2,}\|\-|\r\n|\r|\n/ /g;
        $compliance_value =~ s/ {2,}\|\-|\r\n|\r|\n/ /g;
        $remote_value =~ s/ {2,}/ /g;
        $compliance_value =~ s/ {2,}/ /g;
        my $description = $_->{vuln}->{description};
        $description =~ s/ {2,}\|\-|\r\n|\r|\n/ /g;
        $description =~ s/ {2,}/ /g;
        $_->{vuln}->{plugin_type} = $compliance_check_name[0];
        $Compliance_worksheet->write($Compliance_ctr, 0, $_->{'file'},$cell_format);
        $Compliance_worksheet->write($Compliance_ctr, 1, $_->{'name'},$cell_format);
        $Compliance_worksheet->write($Compliance_ctr, 2, $_->{'fqdn'},$cell_format);
        $Compliance_worksheet->write($Compliance_ctr, 3, $_->{vuln}->{-pluginID},$cell_format);#PluginID
        #$Compliance_worksheet->write($Compliance_ctr, 4, $_->{vuln}->{-protocol},$cell_format);#protocol
        $Compliance_worksheet->write($Compliance_ctr, 4, $_->{vuln}->{-severity},$cell_format);#severity
        #$Compliance_worksheet->write($Compliance_ctr, 5, $_->{vuln}->{-pluginFamily},$cell_format);#pluginFamily
        $Compliance_worksheet->write($Compliance_ctr, 5, $_->{vuln}->{"cm:compliance-audit-file"},$cell_format);
        #$Compliance_worksheet->write($Compliance_ctr, 6, $compliance_check_name[0],$cell_format); #'Policy Type'
        $Compliance_worksheet->write($Compliance_ctr, 6, $_->{vuln}->{"cm:compliance-check-name"},$cell_format);#Check Name
        $Compliance_worksheet->write($Compliance_ctr, 7, $_->{vuln}->{'cm:compliance-result'},$wrap_text_format);#Result
        if ($_->{vuln}->{'cm:compliance-actual-value'} =~ /\=/) {$Compliance_worksheet->write($Compliance_ctr, 8, "\'$_->{vuln}->{'cm:compliance-actual-value'}",$wrap_text_format);} #System Value
        else{$Compliance_worksheet->write($Compliance_ctr, 8, $_->{vuln}->{'cm:compliance-actual-value'},$wrap_text_format);}#System Value
        $Compliance_worksheet->write($Compliance_ctr, 9, $_->{vuln}->{"cm:compliance-policy-value"},$cell_format);#Compliance Requirement
        $Compliance_worksheet->write($Compliance_ctr, 10, $_->{vuln}->{"cm:compliance-info"},$cell_format);#description of test

        ## JB Init Changes
        # Add write for soluton data
        $Compliance_worksheet->write($Compliance_ctr, 11, $_->{vuln}->{'cm:compliance-solution'},$wrap_text_format);#Solution
        $Compliance_worksheet->write($Compliance_ctr, 12, $_->{vuln}->{'cm:compliance-see-also'},$wrap_text_format);#See Also
        my $references = $_->{vuln}->{'cm:compliance-reference'};
        $references =~ s/,/, /g;
        $Compliance_worksheet->write($Compliance_ctr, 13, $references,$wrap_text_format);#XRef
        ## End Init Changes

        ++$Compliance_ctr;
        $_->{vuln}->{'oringnal description'} = $_->{vuln}->{description};
        $_->{vuln}->{'Result'} = $_->{vuln}->{'cm:compliance-result'};
        $_->{vuln}->{'Policy Setting'} = $compliance_check_name[1];
        $_->{vuln}->{'plugin_type'} = $compliance_check_name[0];
        $_->{vuln}->{'remote_value'} = $_->{vuln}->{'cm:compliance-actual-value'};
        $_->{vuln}->{'compliance_value'} = $compliance_value;
        $_->{vuln}->{'description'} = $description;
        if ($_->{vuln}->{description} =~ /(?<=^\").+?(?=\")/ism){$_->{vuln}->{'short description'} = substr($_->{vuln}->{description},$-[0],$+[0]-$-[0]);}
        $compliance_summary{$_->{vuln}->{-pluginName}}->{$_->{vuln}->{'cm:compliance-check-name'}}->{$_->{vuln}->{"cm:compliance-result"}}++;
        $audit_result_type{$_->{vuln}->{"cm:compliance-result"}}++;
    }
    # end foreach (@Compliance)
    return $Compliance_worksheet;
}
# end of sub compliance_worksheet

sub host_summary_data {
    my @host_data = @{$_[0]};
    my $search_item = $_[1];
    my %host_seen_cnt;
    my @Host_uniq_cnt;
    foreach my $item (@host_data){
        if ($search_item =~ /sev/){$host_seen_cnt{$item->{vuln_cnt}->{$search_item}}++}
        else{$host_seen_cnt{$item->{$search_item}}++}
    }
    return %host_seen_cnt;
}
# end of sub host_summary_data

sub get_vuln_cnt{
    my @vuln_array = @{$_[0]};
    my %vuln_cnt = %{$_[1]};
    my $plugin_family = $vuln_array[0]->{-pluginFamily};
    if ($plugin_family eq ""){$plugin_family = "PortScan";}
    my $sev0 = grep {$_->{-severity} == 0} @vuln_array;
    my $sev1 = grep {$_->{-severity} == 1} @vuln_array;
    my $sev2 = grep {$_->{-severity} == 2} @vuln_array;
    my $sev3 = grep {$_->{-severity} == 3} @vuln_array;
    my $sev4 = grep {$_->{-severity} == 4} @vuln_array;
    $vuln_cnt{sev0} = $vuln_cnt{sev0} + $sev0;
    $vuln_cnt{sev1} = $vuln_cnt{sev1} + $sev1;
    $vuln_cnt{sev2} = $vuln_cnt{sev2} + $sev2;
    $vuln_cnt{sev3} = $vuln_cnt{sev3} + $sev3;
    $vuln_cnt{sev4} = $vuln_cnt{sev4} + $sev4;
    my %hash = (
        sev0 => $sev0,  
        sev1 => $sev1,
        sev2 => $sev2,
        sev3 => $sev3,
        sev4 => $sev4
    );
    my %h2 = %hash;
    $vuln_cnt{$plugin_family} = \%h2;
    return %vuln_cnt;
}
# end of sub get_vuln_cnt

sub vuln_seperate_by_plugin {
    my @plugin_data = @{$_[0]};
    my @return_data;
    my %seen;
    my @uniq;
    foreach my $item (@plugin_data){my @tmp = split /\,/, $item;$seen{$tmp[5]}++}
    @return_data = keys %seen;
    foreach my $e (@return_data){
        my %hash;
        $hash{$e} = grep {$_ =~ /,$e,/} @plugin_data;
        my @temp = grep {$_ =~ /,$e,/} @plugin_data;
        my $header = ["plugin id0","Severity1","count2","plugin Name3","File4","plugin Family5","Bid6","CVE7","OSVDB8","Solution9","Description10"];
        my $pivot_data = \@temp;
        foreach my $p (@{$pivot_data}){
            my @tmp = split /\,/,$p;
            $p = ["$tmp[0]","$tmp[1]","$tmp[2]","$tmp[3]","$tmp[4]","$tmp[5]","$tmp[6]","$tmp[7]","$tmp[8]","$tmp[9]","$tmp[10]"];
        }
        my $t = new Data::Table($pivot_data, $header, 0);
        $t->sort("count2",0,1,"CVE7",1,0,"OSVDB8",1,0);
        my @t = @{$t->{data}};
        undef @temp;
        @temp = splice @t,0,10;
        $hash{'entries'} = \@temp;
        $e = \%hash;
    }
    return @return_data,
}
#  end of the seperate_by_plugin

sub store_ad_users{
    my $user_list = $_[0];
    $user_list =~ s/ {2,}- |\)//g;
    $user_list =~ s/ \(/\|/g;
    $user_list =~ s/\, /\|/g;
    @ADUsers = split /\r\n|\r|\n/, $user_list;
    if($ADUsers[0] eq ""){shift @ADUsers}
    my $user_list_cnt = @ADUsers;
    my $splice_cnt = 0;
    if($ADUsers[0] eq ""){shift @ADUsers}
    foreach (@ADUsers){if ($_ eq ""){last;}++$splice_cnt;}
    splice @ADUsers,$splice_cnt;   
    foreach (@ADUsers){
        my @tmp = split /\|/, $_;
        my %hash;
        $hash{'name'} = $tmp[0];
        $hash{'sid'} = $tmp[1];
        if ($tmp[2] eq "Administrator account"){$hash{'type'} = "Domain Administrator account";}
        elsif ($tmp[2] eq "Guest account"){$hash{'type'} = "Domain Guest account";}
        elsif ($tmp[0] =~ /\$$/){$hash{'type'} = "Computer Account";}
        else{$hash{'type'} = "Domain User";}
        $_ = \%hash;
    }
}
# end of store_ad_users

sub check_if_vuln_present{
    my $vuln = $_[0];
    my $file = $_[1];
    my $plugin = $vuln->{-pluginID};
    my $severity = $vuln->{-severity};
    my $key = "$plugin\_$file";
    my $pluginName = $vuln->{-pluginName};
    $pluginName =~ s/\,//g;
    $vuln->{solution} =~ s/\,/\|/g;
    $vuln->{solution} =~ s/\n|\r/\ /g;
    $vuln->{description} =~ s/\,/\|/g;
    $vuln->{description} =~ s/\n|\r/\ /g;
    my $bid;
    if (ref $vuln->{bid} eq "ARRAY"){$bid = join "|", @{$vuln->{bid}}}
    elsif (ref $vuln->{bid} eq ""){$bid = $vuln->{bid}}
    my $cve;
    if (ref $vuln->{cve} eq "ARRAY"){$cve = join "|", @{$vuln->{cve}}}
    elsif (ref $vuln->{cve} eq ""){$cve = $vuln->{cve}}
    my $xref;
    if (ref $vuln->{xref} eq "ARRAY"){$xref = join "|", @{$vuln->{xref}}}
    elsif (ref $vuln->{xref} eq ""){$xref = $vuln->{xref}}
    
    my $plugin_cnt = 0;
    
    if ($severity == 0){
        # @{$vulnerability_data{nonevuln}}
        my $plugin_test = grep /$vuln->{-pluginID}/, @{$vulnerability_data{nonevuln}};
        my @found_plugin = grep /$vuln->{-pluginID}/, @{$vulnerability_data{nonevuln}};
        
        if ($plugin_test == 0){
            ++$plugin_cnt;
            $plugin = "$plugin\,$severity\,$plugin_cnt\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
            push @{$vulnerability_data{nonevuln}}, $plugin
        }
        else{
            my $found = 0;
            foreach (@{$vulnerability_data{nonevuln}}){
                my @tmp = split /\,/, $_;
                my $entry = "$tmp[0]\_$tmp[4]";
                if ($entry eq $key){++$tmp[2];$_ = join(",",@tmp);$found = 1;last;}
            }
            # end foreach
            if ($found == 0){
                $plugin = "$plugin\,$severity\,1\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
                push @{$vulnerability_data{nonevuln}}, $plugin;
            }
            # end of if
        }
        #end else for test
    }
    elsif ($severity == 1){
        # @{$vulnerability_data{lowvuln}}
        my $plugin_test = grep /$vuln->{-pluginID}/, @{$vulnerability_data{lowvuln}};
        my @found_plugin = grep /$vuln->{-pluginID}/, @{$vulnerability_data{lowvuln}};
        if ($plugin_test == 0){
            ++$plugin_cnt;
            $plugin = "$plugin\,$severity\,$plugin_cnt\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
            push @{$vulnerability_data{lowvuln}}, $plugin
        }
        else{
            my $found = 0;
            foreach (@{$vulnerability_data{lowvuln}}){
                my @tmp = split /\,/, $_;
                my $entry = "$tmp[0]\_$tmp[4]";
                if ($entry eq $key){++$tmp[2];$_ = join(",",@tmp);$found = 1;last;}
            }
            # end foreach
            if ($found == 0){
               $plugin = "$plugin\,$severity\,1\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
                push @{$vulnerability_data{lowvuln}}, $plugin;
            }
            # end if
        } #end else for test
    }
    elsif ($severity == 2){
        my $plugin_test = grep /$vuln->{-pluginID}/, @{$vulnerability_data{medvuln}};
        my @found_plugin = grep /$vuln->{-pluginID}/, @{$vulnerability_data{medvuln}};
        if ($plugin_test == 0){
            ++$plugin_cnt;
            $plugin = "$plugin\,$severity\,$plugin_cnt\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
            push @{$vulnerability_data{medvuln}}, $plugin
        }
        else{
            my $found = 0;
            foreach (@{$vulnerability_data{medvuln}}){
                my @tmp = split /\,/, $_;
                my $entry = "$tmp[0]\_$tmp[4]";
                if ($entry eq $key){++$tmp[2];$_ = join(",",@tmp);$found = 1;last;}
            }
            # end foreach
            if ($found == 0){
                $plugin = "$plugin\,$severity\,1\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
                push @{$vulnerability_data{medvuln}}, $plugin;
            }
            # end if
        }
        #end else for test
    }
    elsif ($severity == 3){
        my $plugin_test = grep /$vuln->{-pluginID}/, @{$vulnerability_data{highvuln}};
        my @found_plugin = grep /$vuln->{-pluginID}/, @{$vulnerability_data{highvuln}};
        if ($plugin_test == 0){
            ++$plugin_cnt;
            $plugin = "$plugin\,$severity\,$plugin_cnt\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
            push @{$vulnerability_data{highvuln}}, $plugin
        }
        else{
            my $found = 0;
            foreach (@{$vulnerability_data{highvuln}}){
                my @tmp = split /\,/, $_;
                my $entry = "$tmp[0]\_$tmp[4]";
                if ($entry eq $key){++$tmp[2];$_ = join(",",@tmp);$found = 1;last;}
            }
            # end foreach
            if ($found == 0){
                $plugin = "$plugin\,$severity\,1\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
                push @{$vulnerability_data{highvuln}}, $plugin;
            }
            # end if
        }
        #end else for test
    }
    elsif ($severity == 4){
        my $plugin_test = grep /$vuln->{-pluginID}/, @{$vulnerability_data{criticalvuln}};
        my @found_plugin = grep /$vuln->{-pluginID}/, @{$vulnerability_data{criticalvuln}};
        if ($plugin_test == 0){
            ++$plugin_cnt;
            $plugin = "$plugin\,$severity\,$plugin_cnt\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
            push @{$vulnerability_data{criticalvuln}}, $plugin
        }
        else{
            my $found = 0;
            foreach (@{$vulnerability_data{criticalvuln}}){
                my @tmp = split /\,/, $_;
                my $entry = "$tmp[0]\_$tmp[4]";
                if ($entry eq $key){++$tmp[2];$_ = join(",",@tmp);$found = 1;last;}
            }
            # end foreach
            if ($found == 0){
                $plugin = "$plugin\,$severity\,1\,$pluginName\,$file\,$vuln->{-pluginFamily},$bid,$cve,$xref,$vuln->{solution},$vuln->{description},$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{solution},$vuln->{synopsis},$vuln->{plugin_publication_date},$vuln->{plugin_modification_date},$vuln->{patch_publication_date},$vuln->{vuln_publication_date}";
                push @{$vulnerability_data{criticalvuln}}, $plugin;
            }
            # the if found statement
        }
        #end else for test
    }
    # end Sev 4 
    # END of Vuln level checks
}
# END OF SUBROUTINE

sub store_vuln{
    my @vuln_array = @{$_[0]};
    my $file = $_[1];
    my $name = $_[2];
    my $host_fqdn = $_[3];
    my $netbios_name = $_[4];
    my $operating_system = $_[5];
    my %hash;
    $hash{'file'} = $file;
    $hash{'name'} = $name;
    $hash{'fqdn'} = $host_fqdn;
    $hash{'netbios_name'} = $netbios_name;
    $hash{'operating_system'} = $operating_system;
    print "Storing Vulnerability Data for $name\n";
    
    foreach my $vuln (@vuln_array){
        if ($vuln->{-pluginID} == 33929){print "Removing plugin 33929 from High Vulns calculation\n"}
        elsif ($vuln->{"cm:compliance-result"}) {"removing from the high vulns calculator\n"}
        else {$vuln_totals{$vuln->{-severity}}->{$vuln->{-pluginID}}++;}
        
        if ($vuln->{exploitability_ease} eq ""){$vuln->{exploitability_ease} = "N/A"}
        if ($vuln->{exploit_available} eq ""){$vuln->{exploit_available} = "N/A"}
        if ($vuln->{exploit_framework_canvas} eq ""){$vuln->{exploit_framework_canvas} = "N/A"}
        if ($vuln->{exploit_framework_metasploit} eq ""){$vuln->{exploit_framework_metasploit} = "N/A"}
        if ($vuln->{exploit_framework_core} eq ""){$vuln->{exploit_framework_core} = "N/A"}
        if ($vuln->{metasploit_name} eq ""){$vuln->{metasploit_name} = "N/A"}
        if ($vuln->{canvas_package} eq ""){$vuln->{canvas_package} = "N/A"}
        if ($vuln->{cvss_base_score} eq ""){$vuln->{cvss_base_score} = "N/A"}
        if ($vuln->{cvss_vector} eq ""){$vuln->{cvss_vector} = "N/A"}
        if ($vuln->{cvss_temporal_score} eq ""){$vuln->{cvss_temporal_score} = "N/A"}
        
        if($vuln->{-pluginID} =~ /$port_scan_plugin/){
            $hash{'vuln'} = $vuln;
            my %h2 = %hash;
            push @portScanner,\%h2;
        }
        elsif($vuln->{-pluginID} =~ /$installed_software_plugin/){
            $hash{'vuln'} = $vuln;
            my %h2 = %hash;
            push @installedSoftware,\%h2;
        }
        elsif ($vuln->{-pluginID} =~ /(33931)|(33930)|(33929)|(57581)|(56209)|(56208)/) {
            #33931 - PCI DSS Compliance: Tests Requirements
            #33929 - PCI DSS compliance
            #33930 - PCI DSS Compliance: Passed
            #57581 - PCI DSS Compliance : Database Reachable from the Internet
            #56209 - PCI DSS Compliance : Remote Access Software Has Been Detected
            #56208 - PCI DSS Compliance : Insecure Communication Has Been Detected
            $hash{'vuln'} = $vuln;
            my %h2 = %hash;
            push @PCIDSS,\%h2;
            #print "33929,33930,33931 - PCI DSS Compliance\n";
        }
        elsif($vuln->{-pluginFamily} eq "Policy Compliance"){
            # REMOVE 21156 - Windows Compliance Checks
            # Audit Checks
            if($vuln->{-pluginID} !~ /(66759)|(66757)|(66756)|(66758)|(33931)|(60020)|(33929)|(56209)|(56208)/){
                $hash{'vuln'} = $vuln;
                my %h2 = %hash;
                push @{$complaince{$vuln->{-pluginName}}},\%h2;
                #print "$vuln->{-pluginID} - $vuln->{-pluginName}\n";
                #print "";
            }
            # end of if($vuln->{-pluginID} !~ /(66759)|(66757)|(66756)|(66758)/)
        }
        else{
            if($vuln->{-pluginFamily} eq "" && $vuln->{-pluginName} eq ""){
                $vuln->{-pluginFamily} = "PortScan";
                $vuln->{-pluginName} = "$vuln->{-svc_name}";
                $vuln->{-pluginID} = "$vuln->{-protocol}\-$vuln->{-port}";
            }
            check_if_vuln_present($vuln,$file); 
        }
        # end else statement
        
        if ($vuln->{-pluginName} eq "OS Identification"){
            my @t1 = split /\n/, $vuln->{description};
            my @t2 = split /\:/, $t1[1];
            $vuln->{-pluginName} ="$vuln->{-pluginName} - $t2[1]";
        }
        # end of if ($vuln->{-pluginName} eq "OS Identification")
        
        my $plugin_name = $vuln->{'-pluginName'};
        
        if ($vuln->{plugin_output}) {
            $vuln->{plugin_output} =~ s/\n/\|/g;
            $vuln->{plugin_output} =~ s/\,/ /g;
        }
        # end of if ($vuln->{plugin_output})
        
        if($vuln->{-pluginFamily} ne "Policy Compliance"){
            if($vuln->{'-pluginID'} eq '33929'){
                print "";
            }
            
            my $r = "$file,$name,$host_fqdn,$vuln->{'-pluginID'},$vuln->{'-protocol'},$vuln->{'-port'},$vuln->{'-severity'},$vuln->{'-pluginFamily'},$plugin_name,$vuln->{exploitability_ease},$vuln->{exploit_available},$vuln->{exploit_framework_canvas},$vuln->{exploit_framework_metasploit},$vuln->{exploit_framework_core},$vuln->{metasploit_name},$vuln->{canvas_package},$vuln->{cvss_base_score},$vuln->{cvss_vector},$vuln->{cvss_temporal_score},$vuln->{plugin_output}";
            push @host_scan_data,$r;
        }
        # end of if($vuln->{-pluginFamily} ne "Policy Compliance")
    }
    # end foreach
}
# end of subrooutine

sub normalizeHostData {
    my @report_data = @{$_[0]};
    
    foreach my $host (@report_data){
        my @HostReport;
        my $is_domain_controller = 0;
        my $temp_domain_list;
        $host->{"DomainController"} = "N";
        ####  NEW ARRAYS
        my @aix_local_security_checks;
        my @amazon_linux_local_security_checks;
        my @backdoors;
        my @centos_local_security_checks;
        my @cgi_abuses;
        my @cgi_abuses_xss;
        my @cisco;
        my @databases;
        my @debian_local_security_checks;
        my @default_unix_accounts;
        my @denial_of_service;
        my @dns;
        my @F5_Networks_Local_Security_Checks;
        my @fedora_local_security_checks;
        my @finger_abuses;
        my @firewalls;
        my @freebsd_local_security_checks;
        my @ftp;
        my @gain_a_shell_remotely;
        my @general;
        my @gentoo_local_security_checks;
        my @hp_ux_local_security_checks;
        my @Huawei_Local_Security_Checks;
        my @junos_local_security_checks;
        my @macos_x_local_security_checks;
        my @mandriva_local_security_checks;
        my @misc;
        my @mobile_devices;
        my @netware;
        my @oracle_linux_local_security_checks;
        my @OracleVM_Local_Security_Checks;
        my @peer_to_peer_file_sharing;
        my @Palo_Alto_Local_Security_Checks;
        my @policy_compliance;
        my @port_scanners;
        my @red_hat_local_security_checks;
        my @rpc;
        my @scada;
        my @scientific_linux_local_security_checks;
        my @service_detection;
        my @settings;
        my @slackware_local_security_checks;
        my @smtp_problems;
        my @snmp;
        my @solaris_local_security_checks;
        my @suse_local_security_checks;
        my @ubuntu_local_security_checks;
        my @vmware_esx_local_security_checks;
        my @web_servers;
        my @windows;
        my @windows_microsoft_bulletins;
        my @windows_user_management;
        my @port_scan;
        my @WindowsUserManagement;
        my @IncidentResponse;
        ####  END OF NEW ARRAYS
        
        if(ref ($host->{host_report}) eq "ARRAY"){@HostReport = @{$host->{host_report}};}
        elsif(ref ($host->{host_report}) eq "HASH"){push @HostReport,$host->{host_report};}
        
        foreach my $h_report (@HostReport){
            ###  Find the Domain Controller
            my $is_domain_controller = 0;
            #print "$h_report->{'-pluginID'} \n";
            
            # store data in the %ip_vuln_data hash
            $ip_vuln_data{$host->{file}}->{$h_report->{-severity}}->{$h_report->{-pluginID}}->{pluginName} = $h_report->{-pluginName};
            if ($host->{'host-ip'} eq "") {$ip_vuln_data{$host->{file}}->{$h_report->{-severity}}->{$h_report->{-pluginID}}->{ip}->{$host->{'name'}}++;}
            else{$ip_vuln_data{$host->{file}}->{$h_report->{-severity}}->{$h_report->{-pluginID}}->{ip}->{$host->{'host-ip'}}++;}
            
            # 70329 - process info
            if ($h_report->{-pluginID} == 70329){
                my %process_info = (
                    'fqdn'         => $host->{"host-fqdn"},
                    'host-ip'      => $host->{"host-ip"},
                    'file'         => $host->{file},
                    'name'         => $host->{name},
                    'netbios-name' => $host->{"netbios-name"},
                );
                my $process_info = $h_report->{plugin_output};
                $process_info =~ s/^Process Overview : \n//;
                $process_info =~ s/^SID: Process \(PID\)\n//;
                $process_info =~ s/Process_Information.+process.$//;
                $process_info =~ s/\n\n\n$//;
                my @tmp_process = split /\n/,$process_info;
                foreach my $tp (@tmp_process){
                    my $tp1 = $tp;
                    $tp1 =~ s/^\s\d\s:\s+(((\||)((\-\s)|))|)//;
                    $tp1 =~ s/\s\(\d+\)//;
                    $ms_process_cnt{$tp1}->{$host->{"host-ip"}}++;
                }
                # end of foreach my $tp (@tmp_process)
                $process_info{processes} = \@tmp_process;
                push @MS_Process_Info, \%process_info;
            }
            # end of 70329 - process info
            
            #Device Type
            if ($h_report->{-pluginID} == 54615) {
                my %device_hash = (
                    'fqdn'         => $host->{"host-fqdn"},
                    'host-ip'      => $host->{"host-ip"},
                    'file'         => $host->{file},
                    'name'         => $host->{name},
                    'netbios-name' => $host->{"netbios-name"},
                );
                
                my $deviceData = $h_report->{plugin_output};
                $deviceData =~ s/\n/ /g;
                if ($deviceData =~ /(?<=type : ).*(?=Confidence )/) {$device_hash{type} = substr($deviceData,$-[0],$+[0]-$-[0])}
                if ($deviceData =~ /Confidence level : \d+/) {
                    $device_hash{confidenceLevel} = substr($deviceData,$-[0],$+[0]-$-[0]);
                    $device_hash{confidenceLevel} =~ s/Confidence level : //;
                }
                push @DeviceType, \%device_hash;
            }
            #End of Device Type
            
            # Enumerate Local Group Memberships
            if ($h_report->{-pluginID} == 71246){
                my %EnumLocalGrp = (
                    'fqdn'         => $host->{"host-fqdn"},
                    'host-ip'      => $host->{"host-ip"},
                    'file'         => $host->{file},
                    'name'         => $host->{name},
                    'netbios-name' => $host->{"netbios-name"},
                );
                
                my $EnumLocalGrp = $h_report->{plugin_output};
                $EnumLocalGrp =~ s/\n/;/g;
                my @tmp_grp = split ";;",$EnumLocalGrp;
                foreach my $g (@tmp_grp){
                    my $grp = {};
                    my ($grp_attrib,$members) = split /\;Members/,$g;
                    my @t2 = split /;/,$grp_attrib;
                    foreach my $t3 (@t2){
                        my @t3 = split /\s+:\s/,$t3;
                        $grp->{$t3[0]} = $t3[1];
                    }
                    # end of foreach my $t3 (@t2){
                    if ($members =~ /^\s+:\s$/) {
                        my @t3;
                        push @t3, 'none';
                        $grp->{members} = \@t3;
                    }
                    else{
                        my @t3 = split /;\s+Name\s+:\s+/,$members;
                        if ($t3[0] =~ /\s+\:\s/) {shift @t3}
                        foreach my $t4 (@t3){
                            my $member = {};
                            $t4 = ";  Name : $t4";
                            my @t4 = split /;\s+/,$t4;
                            if ($t4[0] eq '') {shift @t4}
                            foreach my $t5 (@t4){
                                my ($k,$v) = split /\s+:\s+/,$t5;
                                $member->{$k} = $v;
                            }
                            # end of foreach my $t5 (@t4)
                            push @{$grp->{members}},$member
                        }
                        # end of foreach my $t4 (@t3)
                        print "";
                    }
                    # end of if $members
                    print "";
                    $g = $grp;
                }
                # end of foreach my $g (@tmp_grp) 
                $EnumLocalGrp{groups} = \@tmp_grp;
                push @EnumLocalGrp, \%EnumLocalGrp;
            }
            # end of if ($h_report->{-pluginID} == 71246)
            
            # CPE info
            if ($h_report->{cpe}) {
                my %cpe_hash = (
                    'pluginID'     => $h_report->{'-pluginID'},
                    'cpe'          => $h_report->{cpe},
                    'fqdn'         => $host->{"host-fqdn"},
                    'host-ip'      => $host->{"host-ip"},
                    'file'         => $host->{file},
                    'name'         => $host->{name},
                    'netbios-name' => $host->{"netbios-name"},
                    'pluginFamily' => $h_report->{-pluginFamily},
                    'pluginName'   => $h_report->{-pluginName},
                    'cpe-source'   => 'vuln'
                );
                push @cpe_data, \%cpe_hash;
            }
            # end of CPE info
            
            if($h_report->{'-pluginID'} == 45590){
                my @cpe_tmp = split /\n/,$h_report->{plugin_output};
                foreach my $cpe_tmp_e (@cpe_tmp){
                    if ($cpe_tmp_e =~ /cpe\:\/(o|a|h)/) {
                        $cpe_tmp_e =~ s/\s//g;
                        my %cpe_hash = (
                            'pluginID'     => $h_report->{'-pluginID'},
                            'cpe'          => $cpe_tmp_e,
                            'fqdn'         => $host->{"host-fqdn"},
                            'host-ip'      => $host->{"host-ip"},
                            'file'         => $host->{file},
                            'name'         => $host->{name},
                            'netbios-name' => $host->{"netbios-name"},
                            'pluginFamily' => $h_report->{-pluginFamily},
                            'pluginName'   => $h_report->{-pluginName},
                            'cpe-source'   => 'cpe'
                        );
                        push @cpe_data, \%cpe_hash; 
                    }
                    # end of if ($cpe_tmp_e =~ /cpe\:\/(o|a)/)
                }
                #  foreach my $cpe_tmp_e (@cpe_tmp)
            }
            # if($h_report->{'-pluginID'} == 45590)
            
            # @ScanInfo
            if($h_report->{'-pluginID'} == 19506){
                my $scan_info = $h_report;
                $scan_info->{"host-ip"} = $host->{"host-ip"};
                $scan_info->{file} = $host->{file};
                $scan_info->{name} = $host->{name};
                $scan_info->{"operating-system"} = $host->{"operating-system"};
                $scan_info->{"system-type"} = $host->{"system-type"};
                $scan_info->{HOST_END} = $host->{HOST_END};
                $scan_info->{HOST_START} = $host->{HOST_START};
                push @ScanInfo, $scan_info;
            }
            # end of if($h_report->{'-pluginID'} == 19506)
            
            if($opt{r} ne "" && $recast_plugin{$h_report->{'-pluginID'}}->{old} eq $h_report->{-severity}){
                $h_report->{-severity} = $recast_plugin{$h_report->{'-pluginID'}}->{new}
            }
            # end of if($opt{r} ne "" && $recast_plugin{$h_report->{'-pluginID'}}->{old} eq $h_report->{-severity})
            
            if($h_report->{'-pluginID'} =~ /11026/){
                my %wap_host;
                $wap_host{'host-fqdn'} = $host->{'host-fqdn'};
                $wap_host{"host-ip"} = $host->{"host-ip"};
                $wap_host{"mac-address"} = $host->{"mac-address"};
                $wap_host{name} = $host->{name};
                $wap_host{"operating-system"} = $host->{"operating-system"};
                $wap_host{"system-type"} = $host->{"system-type"};
                $wap_host{"plugin-output"} = $h_report->{plugin_output};
                $wap_host{"plugin-output"} =~ s/\n/ /g;
                push @WirelessAccessPointDetection,\%wap_host;
            }
            # end of if($h_report->{'-pluginID'} =~ /11026/)
            
            if($h_report->{'-pluginID'} =~ /25197/){
                my %ssid_host;
                $ssid_host{'host-fqdn'} = $host->{'host-fqdn'};
                $ssid_host{"host-ip"} = $host->{"host-ip"};
                $ssid_host{"mac-address"} = $host->{"mac-address"};
                $ssid_host{name} = $host->{name};
                $ssid_host{"operating-system"} = $host->{"operating-system"};
                $ssid_host{"system-type"} = $host->{"system-type"};
                my $regex_net_card = '(?<=Network card type : ).*($)';
                my $regex_ssid = '(?<=Network SSID      : ).*($)';
                if($h_report->{plugin_output} =~ /$regex_net_card/m){$ssid_host{"nic"} = substr($h_report->{plugin_output},$-[0],$+[0]-$-[0])}
                if($h_report->{plugin_output} =~ /$regex_ssid/m){$ssid_host{"ssid"} = substr($h_report->{plugin_output},$-[0],$+[0]-$-[0])}
                push @WinWirelessSSID, \%ssid_host;
            }
            # end of if($h_report->{'-pluginID'} =~ /25197/)
            
            if($h_report->{'-pluginID'} =~ /10413/  && $ADUsers[0] eq "" && $temp_domain_list eq ""){
                $is_domain_controller = 1;
                $host->{"DomainController"} = "Y";
            }
            elsif($h_report->{'-pluginID'} =~ /10413/  && $ADUsers[0] eq "" && $temp_domain_list ne ""){
                store_ad_users($temp_domain_list);
                $host->{"DomainController"} = "Y";
            }
            elsif($h_report->{'-pluginID'} =~ /10860/ && $ADUsers[0] eq "" && $is_domain_controller == 0){
                $temp_domain_list = $h_report->{plugin_output};
            }
            elsif($h_report->{'-pluginID'} =~ /10860/ && $ADUsers[0] eq "" && $is_domain_controller == 1){
                print "\n\n";print '$h_report->{\'-pluginID\'} =~ /10860/ && $ADUsers[0] eq "" && $is_domain_controller == 1'; 
            }
            elsif($h_report->{'-pluginID'} =~ /10860/ && $ADUsers[0] ne "" && $is_domain_controller == 0){
                $temp_domain_list = $h_report->{plugin_output};
            }
            elsif($h_report->{'-pluginID'} =~ /10413/  && $ADUsers[0] ne "" && $temp_domain_list ne ""){
                store_ad_users($temp_domain_list);
                $host->{"DomainController"} = "Y";
            }
            # end of if..elsif
            
            if($h_report->{-pluginID} =~ /(10413)|(17651)|(10916)|(10915)|(10914)|(10913)|(10912)|(10911)|(10910)|(10908)|(10907)|(10906)|(10905)|(10904)|(10903)|(10902)|(10901)|(10900)|(10899)|(10898)|(10897)|(10896)|(10895)|(10894)|(10893)|(10892)|(10860)|(10399)/){
                #10413 - Microsoft Windows SMB Registry : Remote PDC/BDC Detection
                #17651 - Microsoft Windows SMB : Obtains the Password Policy
                #10916 - Microsoft Windows - Local Users Information : Passwords never expire
                #10915 - Microsoft Windows - Local Users Information : User has never logged on
                #10914 - Microsoft Windows - Local Users Information : Never changed passwords
                #10913 - Microsoft Windows - Local Users Information : Disabled accounts
                #10912 - Microsoft Windows - Local Users Information : Can't change password
                #10911 - Microsoft Windows - Local Users Information : Automatically disabled accounts
                #10910 - Microsoft Windows Local User Information
                #10908 - Microsoft Windows 'Domain Administrators' Group User List
                #10907 - Microsoft Windows Guest Account Belongs to a Group
                #10906 - Microsoft Windows 'Replicator' Group User List
                #10905 - Microsoft Windows 'Print Operators' Group User List
                #10904 - Microsoft Windows 'Backup Operators' Group User List
                #10903 - Microsoft Windows 'Server Operators' Group User List
                #10902 - Microsoft Windows 'Administrators' Group User List
                #10901 - Microsoft Windows 'Account Operators' Group User List
                #10900 - Microsoft Windows - Users Information : Passwords never expires
                #10899 - Microsoft Windows - Users Information : User has never logged in
                #10898 - Microsoft WIndows - Users Information : Never changed password
                #10897 - Microsoft Windows - Users Information : disabled accounts
                #10896 - Microsoft Windows - Users Information : Can't change password
                #10895 - Microsoft Windows - Users Information : automatically disabled accounts
                #10894 - Microsoft Windows User Groups List
                #10893 - Microsoft Windows User Aliases List
                #10892 - Microsoft Windows Domain User Information
                #10860 - SMB Use Host SID to Enumerate Local Users
                #10399 - SMB Use Domain SID to Enumerate Users
                push @WindowsUserManagement,$h_report;
            }
            # end of if($h_report->{-pluginID} =~ /10413|17651|10916|10915|10914|10913|10912|10911|10910|10908|10907|10906|10905|10904|10903|10902|10901|10900|10899|10898|10897|10896|10895|10894|10893|10892|10860|10399/)
            
            if($h_report->{-pluginID} =~ /10150/){
                if ($h_report->{plugin_output} =~ /(?<=Computer name\s ).+?(?= {2,}\= Workgroup)/){
                    $host->{'AD Domain Name'} = substr($h_report->{plugin_output},$-[0],$+[0]-$-[0]);
                }
                # end of if
            }
            # end of ifif($h_report->{-pluginID} =~ /10150/)
            if($h_report->{'-pluginFamily'} =~ /AIX Local Security Checks/){push @aix_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Amazon Linux Local Security Checks/){push @amazon_linux_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Backdoors/){push @backdoors, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /CentOS Local Security Checks/){push @centos_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /CGI abuses/){push @cgi_abuses, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /CGI abuses : XSS/){push @cgi_abuses_xss, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /CISCO/){push @cisco, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Databases/){push @databases, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Debian Local Security Checks/){push @debian_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Default Unix Accounts/){push @default_unix_accounts, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Denial of Service/){push @denial_of_service, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /DNS/){push @dns, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /F5 Networks Local Security Checks/){push @F5_Networks_Local_Security_Checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Fedora Local Security Checks/){push @fedora_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Finger abuses/){push @finger_abuses, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Firewalls/){push @firewalls, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /FreeBSD Local Security Checks/){push @freebsd_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /FTP/){push @ftp, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Gain a shell remotely/){push @gain_a_shell_remotely, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /General/){push @general, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Gentoo Local Security Checks/){push @gentoo_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /HP-UX Local Security Checks/){push @hp_ux_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Huawei Local Security Checks/){push @Huawei_Local_Security_Checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Junos Local Security Checks/){push @junos_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /MacOS X Local Security Checks/){push @macos_x_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Mandriva Local Security Checks/){push @mandriva_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Misc./){push @misc, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Mobile Devices/){push @mobile_devices, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Netware/){push @netware, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /OracleVM Local Security Checks/){push @OracleVM_Local_Security_Checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Oracle Linux Local Security/){push @oracle_linux_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Palo Alto Local Security Checks/){push @Palo_Alto_Local_Security_Checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Peer-To-Peer File Sharing/){push @peer_to_peer_file_sharing, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Policy Compliance/){push @policy_compliance, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Port scanners/){push @port_scanners, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Red Hat Local Security Checks/){push @red_hat_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /RPC/){push @rpc, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /SCADA/){push @scada, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Scientific Linux Local Security Checks/){push @scientific_linux_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Service detection/){push @service_detection, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Settings/){push @settings, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Slackware Local Security Checks/){push @slackware_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /SMTP problems/){push @smtp_problems, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /SNMP/){push @snmp, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Solaris Local Security Checks/){push @solaris_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /SuSE Local Security Checks/){push @suse_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Ubuntu Local Security Checks/){push @ubuntu_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /VMware ESX Local Security Checks/){push @vmware_esx_local_security_checks, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Web Servers/){push @web_servers, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Windows : Microsoft Bulletins/){push @windows_microsoft_bulletins, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Windows : User management/){push @windows_user_management, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Windows/){push @windows, $h_report;}
            elsif($h_report->{'-pluginFamily'} =~ /Incident Response/){push @IncidentResponse, $h_report;}
            elsif($h_report->{'-pluginFamily'} eq ""){push @port_scan, $h_report;}
            else{ print "\nThere is a new plugin family added, it is $h_report->{'-pluginFamily'}\n";exit;}
            
            if ($h_report->{cvss_base_score} || $h_report->{cvss_vector} || $h_report->{cvss_temporal_score}) {
                if (not defined $cvss_score{$host->{"host-ip"}}) {
                    $cvss_score{$host->{"host-ip"}}->{critical_base_score} = 0;
                    $cvss_score{$host->{"host-ip"}}->{high_base_score} = 0;
                    $cvss_score{$host->{"host-ip"}}->{med_base_score} = 0;
                    $cvss_score{$host->{"host-ip"}}->{critical_temporal_score} = 0;
                    $cvss_score{$host->{"host-ip"}}->{high_temporal_score} = 0;
                    $cvss_score{$host->{"host-ip"}}->{med_temporal_score} = 0;
                }
                # end of if (not defined $cvss_score{$host->{"host-ip"}})
                if ($h_report->{-severity} == 4) {
                    if ($h_report->{cvss_base_score} ne "N/A") {$cvss_score{$host->{"host-ip"}}->{critical_base_score} = $cvss_score{$host->{"host-ip"}}->{critical_base_score} + $h_report->{cvss_base_score}}
                    if ($h_report->{cvss_temporal_score} ne "N/A") {$cvss_score{$host->{"host-ip"}}->{critical_temporal_score} = $cvss_score{$host->{"host-ip"}}->{critical_temporal_score} + $h_report->{cvss_temporal_score}}
                }
                elsif ($h_report->{-severity} == 3) {
                    
                    if ($h_report->{cvss_base_score} ne "N/A") {$cvss_score{$host->{"host-ip"}}->{high_base_score} = $cvss_score{$host->{"host-ip"}}->{high_base_score} + $h_report->{cvss_base_score}}
                    if ($h_report->{cvss_temporal_score} ne "N/A") {$cvss_score{$host->{"host-ip"}}->{high_temporal_score} = $cvss_score{$host->{"host-ip"}}->{high_temporal_score} + $h_report->{cvss_temporal_score}}
                }
                elsif ($h_report->{-severity} == 2) {
                    if ($h_report->{cvss_base_score} ne "N/A") {$cvss_score{$host->{"host-ip"}}->{med_base_score} = $cvss_score{$host->{"host-ip"}}->{med_base_score} + $h_report->{cvss_base_score}}
                    if ($h_report->{cvss_temporal_score} ne "N/A") {$cvss_score{$host->{"host-ip"}}->{med_temporal_score} = $cvss_score{$host->{"host-ip"}}->{med_temporal_score} + $h_report->{cvss_temporal_score}}
                }
            }
            # end of if ($h_report->{cvss_base_score} || $h_report->{cvss_vector} || $h_report->{cvss_temporal_score})
        }
        # end of foreach my $h_report (@HostReport)
        
        my @u = @WindowsUserManagement;
        $host->{"WindowsUserManagement"} = \@u;
        my %vuln_cnt;
        $vuln_cnt{sev0} = 0;
        $vuln_cnt{sev1} = 0;
        $vuln_cnt{sev2} = 0;
        $vuln_cnt{sev3} = 0;
        $vuln_cnt{sev4} = 0;
        if($aix_local_security_checks[0] ne ""){$host->{'aix_local_security_checks'} = \@aix_local_security_checks;%vuln_cnt = get_vuln_cnt(\@aix_local_security_checks,\%vuln_cnt)}
        if($amazon_linux_local_security_checks[0] ne ""){$host->{'amazon_linux_local_security_checks'} = \@amazon_linux_local_security_checks;%vuln_cnt = get_vuln_cnt(\@amazon_linux_local_security_checks,\%vuln_cnt)}
        if($backdoors[0] ne ""){$host->{'backdoors'} = \@backdoors;%vuln_cnt = get_vuln_cnt(\@backdoors,\%vuln_cnt)}
        if($centos_local_security_checks[0] ne ""){$host->{'centos_local_security_checks'} = \@centos_local_security_checks;%vuln_cnt = get_vuln_cnt(\@centos_local_security_checks,\%vuln_cnt)}
        if($cgi_abuses[0] ne ""){$host->{'cgi_abuses'} = \@cgi_abuses;%vuln_cnt = get_vuln_cnt(\@cgi_abuses,\%vuln_cnt)}
        if($cgi_abuses_xss[0] ne ""){$host->{'cgi_abuses_xss'} = \@cgi_abuses_xss;%vuln_cnt = get_vuln_cnt(\@cgi_abuses_xss,\%vuln_cnt)}
        if($cisco[0] ne ""){$host->{'cisco'} = \@cisco;%vuln_cnt = get_vuln_cnt(\@cisco,\%vuln_cnt)}
        if($databases[0] ne ""){$host->{'databases'} = \@databases;%vuln_cnt = get_vuln_cnt(\@databases,\%vuln_cnt)}
        if($debian_local_security_checks[0] ne ""){$host->{'debian_local_security_checks'} = \@debian_local_security_checks;%vuln_cnt = get_vuln_cnt(\@debian_local_security_checks,\%vuln_cnt)}
        if($default_unix_accounts[0] ne ""){$host->{'default_unix_accounts'} = \@default_unix_accounts;%vuln_cnt = get_vuln_cnt(\@default_unix_accounts,\%vuln_cnt)}
        if($denial_of_service[0] ne ""){$host->{'denial_of_service'} = \@denial_of_service;%vuln_cnt = get_vuln_cnt(\@denial_of_service,\%vuln_cnt)}
        if($dns[0] ne ""){$host->{'dns'} = \@dns;%vuln_cnt = get_vuln_cnt(\@dns,\%vuln_cnt)}
        if($F5_Networks_Local_Security_Checks[0] ne ""){$host->{'F5_Networks_Local_Security_Checks'} = \@F5_Networks_Local_Security_Checks;%vuln_cnt = get_vuln_cnt(\@F5_Networks_Local_Security_Checks,\%vuln_cnt)}
        if($fedora_local_security_checks[0] ne ""){$host->{'fedora_local_security_checks'} = \@fedora_local_security_checks;%vuln_cnt = get_vuln_cnt(\@fedora_local_security_checks,\%vuln_cnt)}
        if($finger_abuses[0] ne ""){$host->{'finger_abuses'} = \@finger_abuses;%vuln_cnt = get_vuln_cnt(\@finger_abuses,\%vuln_cnt)}
        if($firewalls[0] ne ""){$host->{'firewalls'} = \@firewalls;%vuln_cnt = get_vuln_cnt(\@firewalls,\%vuln_cnt)}
        if($freebsd_local_security_checks[0] ne ""){$host->{'freebsd_local_security_checks'} = \@freebsd_local_security_checks;%vuln_cnt = get_vuln_cnt(\@freebsd_local_security_checks,\%vuln_cnt)}
        if($ftp[0] ne ""){$host->{'ftp'} = \@ftp;%vuln_cnt = get_vuln_cnt(\@ftp,\%vuln_cnt)}
        if($gain_a_shell_remotely[0] ne ""){$host->{'gain_a_shell_remotely'} = \@gain_a_shell_remotely;%vuln_cnt = get_vuln_cnt(\@gain_a_shell_remotely,\%vuln_cnt)}
        if($general[0] ne ""){$host->{'general'} = \@general;%vuln_cnt = get_vuln_cnt(\@general,\%vuln_cnt)}
        if($gentoo_local_security_checks[0] ne ""){$host->{'gentoo_local_security_checks'} = \@gentoo_local_security_checks;%vuln_cnt = get_vuln_cnt(\@gentoo_local_security_checks,\%vuln_cnt)}
        if($hp_ux_local_security_checks[0] ne ""){$host->{'hp_ux_local_security_checks'} = \@hp_ux_local_security_checks;%vuln_cnt = get_vuln_cnt(\@hp_ux_local_security_checks,\%vuln_cnt)}
        if($Huawei_Local_Security_Checks[0] ne ""){$host->{'Huawei_Local_Security_Checks'} = \@Huawei_Local_Security_Checks;%vuln_cnt = get_vuln_cnt(\@Huawei_Local_Security_Checks,\%vuln_cnt)}
        if($junos_local_security_checks[0] ne ""){$host->{'junos_local_security_checks'} = \@junos_local_security_checks;%vuln_cnt = get_vuln_cnt(\@junos_local_security_checks,\%vuln_cnt)}
        if($macos_x_local_security_checks[0] ne ""){$host->{'macos_x_local_security_checks'} = \@macos_x_local_security_checks;%vuln_cnt = get_vuln_cnt(\@macos_x_local_security_checks,\%vuln_cnt)}
        if($mandriva_local_security_checks[0] ne ""){$host->{'mandriva_local_security_checks'} = \@mandriva_local_security_checks;%vuln_cnt = get_vuln_cnt(\@mandriva_local_security_checks,\%vuln_cnt)}
        if($misc[0] ne ""){$host->{'misc'} = \@misc;%vuln_cnt = get_vuln_cnt(\@misc,\%vuln_cnt)}
        if($mobile_devices[0] ne ""){$host->{'mobile_devices'} = \@mobile_devices;%vuln_cnt = get_vuln_cnt(\@mobile_devices,\%vuln_cnt)}
        if($netware[0] ne ""){$host->{'netware'} = \@netware;%vuln_cnt = get_vuln_cnt(\@netware,\%vuln_cnt)}
        if($OracleVM_Local_Security_Checks[0] ne ""){$host->{'OracleVM_Local_Security_Checks'} = \@OracleVM_Local_Security_Checks;%vuln_cnt = get_vuln_cnt(\@OracleVM_Local_Security_Checks,\%vuln_cnt)}
        if($oracle_linux_local_security_checks[0] ne ""){$host->{'oracle_linux_local_security_checks'} = \@oracle_linux_local_security_checks;%vuln_cnt = get_vuln_cnt(\@oracle_linux_local_security_checks,\%vuln_cnt)}
        if($Palo_Alto_Local_Security_Checks[0] ne ""){$host->{'Palo_Alto_Local_Security_Checks'} = \@Palo_Alto_Local_Security_Checks;%vuln_cnt = get_vuln_cnt(\@Palo_Alto_Local_Security_Checks,\%vuln_cnt)}
        if($peer_to_peer_file_sharing[0] ne ""){$host->{'peer_to_peer_file_sharing'} = \@peer_to_peer_file_sharing;%vuln_cnt = get_vuln_cnt(\@peer_to_peer_file_sharing,\%vuln_cnt)}
        if($policy_compliance[0] ne ""){$host->{'policy_compliance'} = \@policy_compliance;}
        if($port_scanners[0] ne ""){$host->{'port_scanners'} = \@port_scanners;%vuln_cnt = get_vuln_cnt(\@port_scanners,\%vuln_cnt)}
        if($red_hat_local_security_checks[0] ne ""){$host->{'red_hat_local_security_checks'} = \@red_hat_local_security_checks;%vuln_cnt = get_vuln_cnt(\@red_hat_local_security_checks,\%vuln_cnt)}
        if($rpc[0] ne ""){$host->{'rpc'} = \@rpc;%vuln_cnt = get_vuln_cnt(\@rpc,\%vuln_cnt)}
        if($scada[0] ne ""){$host->{'scada'} = \@scada;%vuln_cnt = get_vuln_cnt(\@scada,\%vuln_cnt)}
        if($scientific_linux_local_security_checks[0] ne ""){$host->{'scientific_linux_local_security_checks'} = \@scientific_linux_local_security_checks;%vuln_cnt = get_vuln_cnt(\@scientific_linux_local_security_checks,\%vuln_cnt)}
        if($service_detection[0] ne ""){$host->{'service_detection'} = \@service_detection;%vuln_cnt = get_vuln_cnt(\@service_detection,\%vuln_cnt)}
        if($settings[0] ne ""){$host->{'settings'} = \@settings;%vuln_cnt = get_vuln_cnt(\@settings,\%vuln_cnt)}
        if($slackware_local_security_checks[0] ne ""){$host->{'slackware_local_security_checks'} = \@slackware_local_security_checks;%vuln_cnt = get_vuln_cnt(\@slackware_local_security_checks,\%vuln_cnt)}
        if($smtp_problems[0] ne ""){$host->{'smtp_problems'} = \@smtp_problems;%vuln_cnt = get_vuln_cnt(\@smtp_problems,\%vuln_cnt)}
        if($snmp[0] ne ""){$host->{'snmp'} = \@snmp;%vuln_cnt = get_vuln_cnt(\@snmp,\%vuln_cnt)}
        if($solaris_local_security_checks[0] ne ""){$host->{'solaris_local_security_checks'} = \@solaris_local_security_checks;%vuln_cnt = get_vuln_cnt(\@solaris_local_security_checks,\%vuln_cnt)}
        if($suse_local_security_checks[0] ne ""){$host->{'suse_local_security_checks'} = \@suse_local_security_checks;%vuln_cnt = get_vuln_cnt(\@suse_local_security_checks,\%vuln_cnt)}
        if($ubuntu_local_security_checks[0] ne ""){$host->{'ubuntu_local_security_checks'} = \@ubuntu_local_security_checks;%vuln_cnt = get_vuln_cnt(\@ubuntu_local_security_checks,\%vuln_cnt)}
        if($vmware_esx_local_security_checks[0] ne ""){$host->{'vmware_esx_local_security_checks'} = \@vmware_esx_local_security_checks;%vuln_cnt = get_vuln_cnt(\@vmware_esx_local_security_checks,\%vuln_cnt)}
        if($web_servers[0] ne ""){$host->{'web_servers'} = \@web_servers;%vuln_cnt = get_vuln_cnt(\@web_servers,\%vuln_cnt)}
        if($windows_microsoft_bulletins[0] ne ""){$host->{'windows_microsoft_bulletins'} = \@windows_microsoft_bulletins;%vuln_cnt = get_vuln_cnt(\@windows_microsoft_bulletins,\%vuln_cnt)}
        if($windows_user_management[0] ne ""){$host->{'windows_user_management'} = \@windows_user_management;%vuln_cnt = get_vuln_cnt(\@windows_user_management,\%vuln_cnt)}
        if($windows[0] ne ""){$host->{'windows'} = \@windows;%vuln_cnt = get_vuln_cnt(\@windows,\%vuln_cnt)}
        if($port_scan[0] ne ""){$host->{'port_scan'} = \@port_scan;%vuln_cnt = get_vuln_cnt(\@port_scan,\%vuln_cnt)}
        if($IncidentResponse[0] ne ""){$host->{'IncidentResponse'} = \@IncidentResponse;%vuln_cnt = get_vuln_cnt(\@IncidentResponse,\%vuln_cnt);}
        
        $host->{'vuln_cnt'} = \%vuln_cnt;
    }
    # end the Policy Compliance foreach loop
    print "\nFinished Parsing XML Data\n\n";
    
    # General Vulnerability Report
    print "Create General Vulnerability Data\n";
    foreach my $host (@report_data){
        my @report_data;
        if (ref $host->{host_report} eq "HASH"){push @report_data, $host->{host_report};}
        else{@report_data = @{$host->{host_report}};}
        my $name = $host->{name};
        if (not defined $host->{'host-fqdn'}){$host->{'host-fqdn'} = "N/A";}
        if($host->{'aix_local_security_checks'}->[0] ne ""){store_vuln($host->{'aix_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'amazon_linux_local_security_checks'}->[0] ne ""){store_vuln($host->{'amazon_linux_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'backdoors'}->[0] ne ""){store_vuln($host->{'backdoors'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'centos_local_security_checks'}->[0] ne ""){store_vuln($host->{'centos_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'cgi_abuses'}->[0] ne ""){store_vuln($host->{'cgi_abuses'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'cgi_abuses_xss'}->[0] ne ""){store_vuln($host->{'cgi_abuses_xss'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'cisco'}->[0] ne ""){store_vuln($host->{'cisco'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'databases'}->[0] ne ""){store_vuln($host->{'databases'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'debian_local_security_checks'}->[0] ne ""){store_vuln($host->{'debian_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'default_unix_accounts'}->[0] ne ""){store_vuln($host->{'default_unix_accounts'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'denial_of_service'}->[0] ne ""){store_vuln($host->{'denial_of_service'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'dns'}->[0] ne ""){store_vuln($host->{'dns'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'F5_Networks_Local_Security_Checks'}->[0] ne ""){store_vuln($host->{'F5_Networks_Local_Security_Checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'fedora_local_security_checks'}->[0] ne ""){store_vuln($host->{'fedora_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'finger_abuses'}->[0] ne ""){store_vuln($host->{'finger_abuses'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'firewalls'}->[0] ne ""){store_vuln($host->{'firewalls'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'freebsd_local_security_checks'}->[0] ne ""){store_vuln($host->{'freebsd_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'ftp'}->[0] ne ""){store_vuln($host->{'ftp'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'gain_a_shell_remotely'}->[0] ne ""){store_vuln($host->{'gain_a_shell_remotely'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'general'}->[0] ne ""){store_vuln($host->{'general'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'gentoo_local_security_checks'}->[0] ne ""){store_vuln($host->{'gentoo_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'hp_ux_local_security_checks'}->[0] ne ""){store_vuln($host->{'hp_ux_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'Huawei_Local_Security_Checks'}->[0] ne ""){store_vuln($host->{'Huawei_Local_Security_Checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'IncidentResponse'}->[0] ne ""){store_vuln($host->{'IncidentResponse'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'junos_local_security_checks'}->[0] ne ""){store_vuln($host->{'junos_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'macos_x_local_security_checks'}->[0] ne ""){store_vuln($host->{'macos_x_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'mandriva_local_security_checks'}->[0] ne ""){store_vuln($host->{'mandriva_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'misc'}->[0] ne ""){store_vuln($host->{'misc'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'mobile_devices'}->[0] ne ""){store_vuln($host->{'mobile_devices'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'netware'}->[0] ne ""){store_vuln($host->{'netware'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'OracleVM_Local_Security_Checks'}->[0] ne ""){store_vuln($host->{'OracleVM_Local_Security_Checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'oracle_linux_local_security_checks'}->[0] ne ""){store_vuln($host->{'oracle_linux_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'Palo_Alto_Local_Security_Checks'}->[0] ne ""){store_vuln($host->{'Palo_Alto_Local_Security_Checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'peer_to_peer_file_sharing'}->[0] ne ""){store_vuln($host->{'peer_to_peer_file_sharing'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'policy_compliance'}->[0] ne ""){store_vuln($host->{'policy_compliance'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'port_scanners'}->[0] ne ""){store_vuln($host->{'port_scanners'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'red_hat_local_security_checks'}->[0] ne ""){store_vuln($host->{'red_hat_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'rpc'}->[0] ne ""){store_vuln($host->{'rpc'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'scada'}->[0] ne ""){store_vuln($host->{'scada'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'scientific_linux_local_security_checks'}->[0] ne ""){store_vuln($host->{'scientific_linux_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'service_detection'}->[0] ne ""){store_vuln($host->{'service_detection'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'settings'}->[0] ne ""){store_vuln($host->{'settings'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'slackware_local_security_checks'}->[0] ne ""){store_vuln($host->{'slackware_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'smtp_problems'}->[0] ne ""){store_vuln($host->{'smtp_problems'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'snmp'}->[0] ne ""){store_vuln($host->{'snmp'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'solaris_local_security_checks'}->[0] ne ""){store_vuln($host->{'solaris_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'suse_local_security_checks'}->[0] ne ""){store_vuln($host->{'suse_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'ubuntu_local_security_checks'}->[0] ne ""){store_vuln($host->{'ubuntu_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'vmware_esx_local_security_checks'}->[0] ne ""){store_vuln($host->{'vmware_esx_local_security_checks'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'web_servers'}->[0] ne ""){store_vuln($host->{'web_servers'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'windows_microsoft_bulletins'}->[0] ne ""){store_vuln($host->{'windows_microsoft_bulletins'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"});print "";}
        if($host->{'windows_user_management'}->[0] ne ""){store_vuln($host->{'windows_user_management'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"})}
        if($host->{'windows'}->[0] ne ""){store_vuln($host->{'windows'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"})}
        if($host->{'port_scan'}->[0] ne ""){store_vuln($host->{'port_scan'},$host->{'file'},$host->{name},$host->{'host-fqdn'},$host->{"netbios-name"},$host->{"operating-system"})}
        my @MSWinAccounts;
        my $domain_user_list;
        my $local_user_list;
        my $password_policy;
        my @user_list;
        foreach (@{$host->{'WindowsUserManagement'}}){
            if($_->{-pluginID} =~ /10399|10413/){print "";}
            elsif($_->{-pluginID} =~ /10860/){
                $local_user_list = $_;}
            elsif($_->{-pluginID} =~ /17651/){$password_policy = $_;}
            else{push @MSWinAccounts, $_;}
        }
        #end foreach (@WindowsUserManagement)
        
        if($host->{DomainController} eq "N" && ref $local_user_list eq "HASH"){
            #$local_user_list->{plugin_output} =~ s/ {2,}- |\)//g;
            $local_user_list->{plugin_output} =~ s/( {2,}- )|(\))//g;
            $local_user_list->{plugin_output} =~ s/ \(/\|/g;
            $local_user_list->{plugin_output} =~ s/\, /\|/g;
            $local_user_list->{plugin_output} =~ s/Note that.*$//;
            $local_user_list->{plugin_output} =~ s/\|id/ id/g;
            $local_user_list->{plugin_output} =~ s/^\|//;
            $local_user_list->{plugin_output} =~ s/(\|)+$//;
            $local_user_list->{plugin_output} =~ s/ id /;/g;
            $local_user_list->{plugin_output} =~ s/\s{2,}/;/g;
            
            @user_list = split /\|/, $local_user_list->{plugin_output};
            my $user_list_cnt = @user_list;
            my $splice_cnt = 0;
            if($user_list[0] eq ""){shift @user_list}
            foreach (@user_list){if ($_ eq ""){last;}++$splice_cnt;}
            splice @user_list,$splice_cnt;
            foreach (@user_list){
                my @tmp = split /\;/, $_;
                my %hash;
                $hash{'name'} = $tmp[0];
                $hash{'sid'} = $tmp[1];
                $hash{'type'} = $tmp[2];
                $_ = \%hash;
            }
            # end of foreach (@user_list)
            print "";
        }
        
        foreach my $acnt_entry (@MSWinAccounts){
            my @plugin_data;
            my $act_type;
            if($acnt_entry->{-pluginID} =~ /10895/){$act_type = "Automatic Account Disabled";}
            elsif($acnt_entry->{-pluginID} =~ /10896/){$act_type = "Can't Change Password";}
            elsif($acnt_entry->{-pluginID} =~ /10897/){$act_type = "Account Disabled";}
            elsif($acnt_entry->{-pluginID} =~ /10898/){$act_type = "Never Changed Password";}
            elsif($acnt_entry->{-pluginID} =~ /10899/){$act_type = "Never Logged In";}
            elsif($acnt_entry->{-pluginID} =~ /10900/){$act_type = "Account Disabled";}
            elsif($acnt_entry->{-pluginID} =~ /10911/){$act_type = "Automatic Account Disabled";}
            elsif($acnt_entry->{-pluginID} =~ /10912/){$act_type = "Can't Change Password";}
            elsif($acnt_entry->{-pluginID} =~ /10913/){$act_type = "Account Disabled";}
            elsif($acnt_entry->{-pluginID} =~ /10914/){$act_type = "Never Changed Password";}
            elsif($acnt_entry->{-pluginID} =~ /10915/){$act_type = "Never Logged In";}
            elsif($acnt_entry->{-pluginID} =~ /10916/){$act_type = "Account Disabled";}
            elsif($acnt_entry->{-pluginID} =~ /10901/){$act_type = "Account Operators";}
            elsif($acnt_entry->{-pluginID} =~ /10902/){$act_type = "Administrators";}
            elsif($acnt_entry->{-pluginID} =~ /10903/){$act_type = "Server Operators";}
            elsif($acnt_entry->{-pluginID} =~ /10904/){$act_type = "Backup Operators";}
            elsif($acnt_entry->{-pluginID} =~ /10905/){$act_type = "Print Operators";}
            elsif($acnt_entry->{-pluginID} =~ /10906/){$act_type = "Replicator";}
            elsif($acnt_entry->{-pluginID} =~ /10907/){$act_type = "Guest Account Belongs to a Group";}
            elsif($acnt_entry->{-pluginID} =~ /10908/){$act_type = "Domain Administrators";}
            
            if ($host->{DomainController} eq "N" && $act_type ne ""){
                my $a = $acnt_entry->{plugin_output};
                foreach (@user_list){
                    my $usr_name = $_->{name};
                    if ($usr_name =~ /\\/){$usr_name =~ s/\\/\\\\/g;}
                    my $usr_sid = $_->{sid};
                    if ($acnt_entry->{-pluginID} =~ /(10916)|(10915)|(10914)|(10913)|(10912)|(10911)|(10910)|(10900)|(10899)|(10898)|(10897)|(10896)|(10895)/){
                        my $b = "\(\\s\\s\\-\\s\)$usr_name";
                        if ($a =~ /$b/sm){$_->{$act_type} = "Y"}
                        else{$_->{$act_type} = "N"}
                    }
                    elsif ($acnt_entry->{-pluginID} =~ /(10908)|(10907)|(10906)|(10905)|(10904)|(10903)|(10902)|(10901)/){
                        $usr_name = "$host->{\"netbios-name\"}.$usr_name";
                        if ($a =~ /\Q$usr_name\E/ism){$_->{$act_type} = "Y"}
                        else{$_->{$act_type} = "N"}
                    }
                }
                # end of foreach (@user_list)
                if ($acnt_entry->{-pluginID} =~ /(10908)|(10907)|(10906)|(10905)|(10904)|(10903)|(10902)|(10901)/){
                    my $netbios_name = $host->{"netbios-name"};
                    if($a =~ /(?=\Q$netbios_name\E).+?(\Z)/ism){
                        my $d = substr($a,$-[0],$+[0]-$-[0]);
                        $d =~ s/ {2,}- |\)//g;
                        $d  =~ s/ \(/\|/g;
                        $d  =~ s/\, /\|/g;
                        my @d_list = split /\r\n|\r|\n/, $d;
                        foreach (@d_list){
                            if ($_ !~ /$netbios_name/){
                                my @d1 = split /\|/, $_;
                                my %hash;
                                $hash{'name'} = $d1[0];
                                $hash{'type'} = $d1[1];
                                $hash{$act_type} = "Y";
                                my $not_in_list = 1;
                                foreach my $usr (@user_list){
                                    if($usr->{name} eq $hash{name}){$usr->{$act_type} = "Y";$not_in_list = 0;last;}
                                }
                                if($not_in_list == 1){push @user_list, \%hash;}
                            }
                            # end of if ($_ !~ /$netbios_name/)
                        }
                        # end of foreach (@d_list)
                    }
                    # end of if($a =~ /(?=$netbios_name).+?(\Z)/ism)
                }
                #  end of if ($acnt_entry->{-pluginID} =~ /10908|10907|10906|10905|10904|10903|10902|10901/)
            }
            # end of if ($host->{DomainController} eq "N" && $act_type ne "")
            
            if ($host->{DomainController} eq "Y" && $is_domain_controller_users_checked == 0){
                my $a = $acnt_entry->{plugin_output};
                foreach (@ADUsers){
                    my $usr_name = $_->{name};
                    my $usr_sid = $_->{sid};
                    if ($a =~ /$usr_name/ism){$_->{$act_type} = "Y"}
                    else{$_->{$act_type} = "N"}
                }
                #end of foreach (@ADUsers)
            }
            # end of if ($host->{DomainController} eq "Y" && $is_domain_controller_users_checked == 0)
        }
        # end of foreach my $acnt_entry (@MSWinAccounts)
        if ($host->{DomainController} eq "Y" && $is_domain_controller_users_checked == 0){$is_domain_controller_users_checked = 1;}
        if ($host->{DomainController} eq "N"){
            foreach (@user_list){if ($_->{type} eq ""){$_->{type} = "Local User"}}
            my @new_user_list = @user_list;
            $host->{'account_info'} = \@new_user_list;
        }
        #  end of if ($host->{DomainController} eq "N")
        if ($password_policy ne ""){
            my $p = $password_policy->{plugin_output};
            if($p =~ /(?=Minimum).+?(?=\Z)/ism){$p = substr($p,$-[0],$+[0]-$-[0]);}
            my @p_tmp = split /\|/, $p;
            foreach (@p_tmp){
                my @tmp = split /\:/, $_;
                $tmp[1] =~ s/\s//g;
                $host->{$tmp[0]} = $tmp[1];
            }
            # end of foreach (@p_tmp)
            $host->{'password policy'} = $password_policy;
        }
        #  end of if ($password_policy ne "")
        
        ######  testing to remove the plugin Family Data
        
        delete $host->{'aix_local_security_checks'};
        delete $host->{'amazon_linux_local_security_checks'};
        delete $host->{'backdoors'};
        delete $host->{'centos_local_security_checks'};
        delete $host->{'cgi_abuses'};
        delete $host->{'cgi_abuses_xss'};
        delete $host->{'cisco'};
        delete $host->{'databases'};
        delete $host->{'debian_local_security_checks'};
        delete $host->{'default_unix_accounts'};
        delete $host->{'denial_of_service'};
        delete $host->{'dns'};
        delete $host->{'F5_Networks_Local_Security_Checks'};
        delete $host->{'fedora_local_security_checks'};
        delete $host->{'finger_abuses'};
        delete $host->{'firewalls'};
        delete $host->{'freebsd_local_security_checks'};
        delete $host->{'ftp'};
        delete $host->{'gain_a_shell_remotely'};
        delete $host->{'general'};
        delete $host->{'gentoo_local_security_checks'};
        delete $host->{'hp_ux_local_security_checks'};
        delete $host->{'Huawei_Local_Security_Checks'};
        delete $host->{'IncidentResponse'};
        delete $host->{'junos_local_security_checks'};
        delete $host->{'macos_x_local_security_checks'};
        delete $host->{'mandriva_local_security_checks'};
        delete $host->{'misc'};
        delete $host->{'mobile_devices'};
        delete $host->{'netware'};
        delete $host->{'OracleVM_Local_Security_Checks'};
        delete $host->{'oracle_linux_local_security_checks'};
        delete $host->{'Palo_Alto_Local_Security_Checks'};
        delete $host->{'peer_to_peer_file_sharing'};
        delete $host->{'policy_compliance'};
        delete $host->{'port_scanners'};
        delete $host->{'red_hat_local_security_checks'};
        delete $host->{'rpc'};
        delete $host->{'scada'};
        delete $host->{'scientific_linux_local_security_checks'};
        delete $host->{'service_detection'};
        delete $host->{'settings'};
        delete $host->{'slackware_local_security_checks'};
        delete $host->{'smtp_problems'};
        delete $host->{'snmp'};
        delete $host->{'solaris_local_security_checks'};
        delete $host->{'suse_local_security_checks'};
        delete $host->{'ubuntu_local_security_checks'};
        delete $host->{'vmware_esx_local_security_checks'};
        delete $host->{'web_servers'};
        delete $host->{'windows_microsoft_bulletins'};
        delete $host->{'windows_user_management'};
        delete $host->{'windows'};
        delete $host->{'port_scan'};        
        ######  end removeing plugin data
    }
    # end foreach my $host (@host_data)
    push @host_data, @report_data;
}
# end of sub normalizeHostData

print "\n\n\n Pause for Testing before reading data\n\n";
##############################  END SUBROUTINES


foreach my $file (@xml_files){
    print "---------  Parsing $file\n\n";
    my $tpp = XML::TreePP->new();
    my $tree = $tpp->parsefile( $file );
    if($tree->{NessusClientData_v2}){print "Parsing File $file \n\n";}
    else{print "This file \"$file\" is not using the Nessus version 2 format, please choose the nessus v2 format.\n\n";exit;}
    my @report_data;
    my @t_policy = grep {$_->{name} =~ /targ/i} @{$tree->{NessusClientData_v2}->{Policy}->{Preferences}->{ServerPreferences}->{preference}};
    push @targets, @t_policy;
    if (ref($tree->{NessusClientData_v2}->{Report}->{ReportHost}) eq "HASH"){push @report_data, $tree->{NessusClientData_v2}->{Report}->{ReportHost};}
    elsif (ref($tree->{NessusClientData_v2}->{Report}->{ReportHost}) eq "ARRAY"){@report_data = @{$tree->{NessusClientData_v2}->{Report}->{ReportHost}};}
    foreach my $hostproperties (@report_data){
        my %hash;
        $hash{file} = $file;
        $hash{name} = $hostproperties->{-name};
        my @host;
        if (ref ($hostproperties->{HostProperties}) ne "ARRAY" && ref($hostproperties->{HostProperties}) ne "HASH") {
            ++$total_discovered{$hostproperties->{-name}};
        }
        elsif (ref($hostproperties->{HostProperties}->{tag}) eq "HASH"){
            #++$total_discovered{$hostproperties->{-name}};
            push @host, $hostproperties->{HostProperties}->{tag};
        }
        elsif (ref($hostproperties->{HostProperties}->{tag}) eq "ARRAY"){
            #++$total_discovered{$hostproperties->{-name}};
            @host = @{$hostproperties->{HostProperties}->{tag}};
        }
        $hash{host_report} = $hostproperties->{ReportItem};
        foreach my $host (@host){$hash{$host->{-name}} = $host->{"#text"};}
        # end - foreach my $host_data (@host_data)
        if ($hash{"host-ip"}) {++$total_discovered{$hash{"host-ip"}}}
        
        $hostproperties = \%hash;
    }
    # end foreach my $hostproperties (@host_data)
    
    normalizeHostData (\@report_data);
    
    #push @host_data, @report_data;
    print "Finished Parsing File $file \n\n";
}
# end xml file foreach loop

#my $sizeTest = total_size(\@host_data);

#print "the \@host_data is $sizeTest\n\n";

print "Creating Spreadsheet Data\n";

# Extract Policy Compliance

print "---------------  MOVE THE POLICY ARRAYS TO THE TOP\n\n\n\n";  sleep 3;



print "Creating Nessus Report Spreadsheet\n";
#######################################################  start spreadsheet
$workbook = Excel::Writer::XLSX->new("$dir/$report_prefix\_$report_file.xlsx");
my $Home_worksheet = $workbook->add_worksheet('Home Worksheet');
$home_url = "internal\:\'Home Worksheet\'\!A1";

####  Begin formating entries
$center_format = $workbook->add_format(
    valign => 'vcenter',
    align  => 'center',
);

$center_border6_format = $workbook->add_format(
    valign => 'vleft',
    align  => 'left',
    bold => 1,
    bg_color => 'black',
    color => 9,
    border => 2,
    border_color => 'black',
);

$wrap_text_format = $workbook->add_format(
    valign => 'vleft',
    align  => 'left',
    #text_wrap => 1,
    border => 1,
    border_color => 'black',
);

$cell_format = $workbook->add_format(
    valign => 'vleft',
    align  => 'left',
    border => 1,
    border_color => 'black',
);

$url_format = $workbook->add_format( color => 'blue', underline => 1 );
###  End formating entries

#$worksheet->write_url( 'A1', $home_url, $url_format, $_);

print "Storing Host Scan Data Table\n";
my $host_scan_data_ctr = 2;
my $host_scan_data_worksheet = $workbook->add_worksheet('host_scan_data');
$host_scan_data_worksheet->write_url( 'A1', $home_url, $url_format, $_);
$host_scan_data_worksheet->keep_leading_zeros();
$host_scan_data_worksheet->write(1, 0, 'File',$center_border6_format);
$host_scan_data_worksheet->write(1, 1, 'IP Address',$center_border6_format);
$host_scan_data_worksheet->write(1, 2, 'FQDN',$center_border6_format);
$host_scan_data_worksheet->write(1, 3, 'Plugin ID',$center_border6_format);
$host_scan_data_worksheet->write(1, 4, 'Protocol',$center_border6_format);
$host_scan_data_worksheet->write(1, 5, 'Port',$center_border6_format);
$host_scan_data_worksheet->write(1, 6, 'Severity',$center_border6_format);
$host_scan_data_worksheet->write(1, 7, 'Plugin Family',$center_border6_format);
$host_scan_data_worksheet->write(1, 8, 'Plugin Name',$center_border6_format);
$host_scan_data_worksheet->write(1, 9, 'CVSS Vector',$center_border6_format);
$host_scan_data_worksheet->write(1, 10, 'CVSS Base Score',$center_border6_format);
$host_scan_data_worksheet->write(1, 11, 'CVSS Temporal Score',$center_border6_format);
$host_scan_data_worksheet->write(1, 12, 'Exploitability Ease',$center_border6_format);
$host_scan_data_worksheet->write(1, 13, 'Exploit Available',$center_border6_format);
$host_scan_data_worksheet->write(1, 14, 'Exploit Framework Canvas',$center_border6_format);
$host_scan_data_worksheet->write(1, 15, 'Exploit Framework Metasploit',$center_border6_format);
$host_scan_data_worksheet->write(1, 16, 'Exploit Framework Core',$center_border6_format);
$host_scan_data_worksheet->write(1, 17, 'Metasploit Name',$center_border6_format);
$host_scan_data_worksheet->write(1, 18, 'Canvas Package',$center_border6_format);
$host_scan_data_worksheet->write(1, 19, 'Plugin Output',$center_border6_format);
$host_scan_data_worksheet->freeze_panes('C3');
$host_scan_data_worksheet->autofilter('A2:T2');
$host_scan_data_worksheet->set_tab_color('black');
$host_scan_data_worksheet->set_column('A:A', 20);
$host_scan_data_worksheet->set_column('B:B', 15);
$host_scan_data_worksheet->set_column('C:C', 25);
$host_scan_data_worksheet->set_column('D:G', 10);
$host_scan_data_worksheet->set_column('G:G', 10);
$host_scan_data_worksheet->set_column('H:H', 30);
$host_scan_data_worksheet->set_column('I:I', 60);
$host_scan_data_worksheet->set_column('J:P', 30);
$host_scan_data_worksheet->set_column('R:R', 60);
$host_scan_data_worksheet->set_column('S:S', 15);
$host_scan_data_worksheet->set_column('T:T', 60);

my $h_tmp = @host_scan_data;
my $h_tmp2 = $h_tmp;
my $table_cnt = 2;
if($h_tmp > 100000){
    my $array_cnt = $h_tmp/100000;
    my @dec = split /\./, $array_cnt;
    if ($dec[1] > 0){++$dec[0]}
    $table_cnt = $dec[0];
    $h_tmp = 100000;
}
# end of if($h_tmp > 100000)

foreach (@host_scan_data){
    if ($host_scan_data_ctr == $h_tmp && $h_tmp2 < $host_scan_data_ctr){
        my $table = $table_cnt - 1;
        $host_scan_data_ctr = 1;
        $host_scan_data_worksheet = $workbook->add_worksheet("host_scan_data_$table");
        $host_scan_data_worksheet->write(1, 0, 'File',$center_border6_format);
        $host_scan_data_worksheet->write(1, 1, 'IP Address',$center_border6_format);
        $host_scan_data_worksheet->write(1, 2, 'FQDN',$center_border6_format);
        $host_scan_data_worksheet->write(1, 3, 'Plugin ID',$center_border6_format);
        $host_scan_data_worksheet->write(1, 4, 'Protocol',$center_border6_format);
        $host_scan_data_worksheet->write(1, 5, 'Port',$center_border6_format);
        $host_scan_data_worksheet->write(1, 6, 'Severity',$center_border6_format);
        $host_scan_data_worksheet->write(1, 7, 'Plugin Family',$center_border6_format);
        $host_scan_data_worksheet->write(1, 8, 'Plugin Name',$center_border6_format);
        $host_scan_data_worksheet->write(1, 9, 'CVSS Vector',$center_border6_format);
        $host_scan_data_worksheet->write(1, 10, 'CVSS Base Score',$center_border6_format);
        $host_scan_data_worksheet->write(1, 11, 'CVSS Temporal Score',$center_border6_format);
        $host_scan_data_worksheet->write(1, 12, 'Exploitability Ease',$center_border6_format);
        $host_scan_data_worksheet->write(1, 13, 'Exploit Available',$center_border6_format);
        $host_scan_data_worksheet->write(1, 14, 'Exploit Framework Canvas',$center_border6_format);
        $host_scan_data_worksheet->write(1, 15, 'Exploit Framework Metasploit',$center_border6_format);
        $host_scan_data_worksheet->write(1, 16, 'Exploit Framework Core',$center_border6_format);
        $host_scan_data_worksheet->write(1, 17, 'Metasploit Name',$center_border6_format);
        $host_scan_data_worksheet->write(1, 18, 'Canvas Package',$center_border6_format);
        $host_scan_data_worksheet->write(1, 19, 'Plugin Output',$center_border6_format);
        $host_scan_data_worksheet->freeze_panes('C3');
    }
    # end of if ($host_scan_data_ctr == $h_tmp)
    my @tmp = split /\,/, $_;
    $host_scan_data_worksheet->write($host_scan_data_ctr, 0, $tmp[0],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 1, $tmp[1],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 2, $tmp[2],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 3, $tmp[3],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 4, $tmp[4],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 5, $tmp[5],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 6, $tmp[6],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 7, $tmp[7],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 8, $tmp[8],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 9, $tmp[17],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 10, $tmp[16],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 11, $tmp[18],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 12, $tmp[9],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 13, $tmp[10],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 14, $tmp[11],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 15, $tmp[12],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 16, $tmp[13],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 17, $tmp[14],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 18, $tmp[15],$cell_format);
    $host_scan_data_worksheet->write($host_scan_data_ctr, 19, $tmp[19],$cell_format);
    ++$host_scan_data_ctr;
}
# end foreach (@host_scan_data)

if($ScanInfo[0] ne ""){
    my $ScanInfo_ctr = 2;
    print "Storing Scan Info Data Table\n";
    my $ScanInfo_worksheet = $workbook->add_worksheet('ScanInfo');
    $ScanInfo_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $ScanInfo_worksheet->keep_leading_zeros();
    $ScanInfo_worksheet->write(1, 0, 'File',$center_border6_format);
    $ScanInfo_worksheet->write(1, 1, 'IP Address',$center_border6_format);
    $ScanInfo_worksheet->write(1, 2, 'FQDN',$center_border6_format);
    $ScanInfo_worksheet->write(1, 3, 'Operating System',$center_border6_format);
    $ScanInfo_worksheet->write(1, 4, 'System Type',$center_border6_format);
    $ScanInfo_worksheet->write(1, 5, 'Scan Start',$center_border6_format);
    $ScanInfo_worksheet->write(1, 6, 'Scan End',$center_border6_format);
    $ScanInfo_worksheet->write(1, 7, 'Scan Duration',$center_border6_format);
    $ScanInfo_worksheet->write(1, 8, 'Experimental Tests',$center_border6_format);
    $ScanInfo_worksheet->write(1, 9, 'Credentialed Checks',$center_border6_format);
    $ScanInfo_worksheet->write(1, 10, 'Patch Management Checks',$center_border6_format);
    $ScanInfo_worksheet->write(1, 11, 'Safe Checks',$center_border6_format);
    $ScanInfo_worksheet->write(1, 12, 'CGI Scanning',$center_border6_format);
    $ScanInfo_worksheet->write(1, 13, 'We Application Tests',$center_border6_format);
    $ScanInfo_worksheet->write(1, 14, 'Paranoia level',$center_border6_format);
    $ScanInfo_worksheet->write(1, 15, 'Thorough tests',$center_border6_format);
    $ScanInfo_worksheet->freeze_panes('C3');
    $ScanInfo_worksheet->autofilter('A2:Q2');
    $ScanInfo_worksheet->set_column('A:A', 20);
    $ScanInfo_worksheet->set_column('B:C', 15);
    $ScanInfo_worksheet->set_column('D:G', 25);
    $ScanInfo_worksheet->set_column('H:J', 20);
    $ScanInfo_worksheet->set_column('K:O', 20);
    $ScanInfo_worksheet->set_column('P:P', 20);
    $ScanInfo_worksheet->set_column('Q:Q', 20);
    
    foreach my $e (@ScanInfo){
        my @tmp = split /\|/, $e->{plugin_output};
        shift @tmp;
        shift @tmp;
        foreach (@tmp){my ($k,$v) = split ":",$_;$k = "po-$k";$k =~ s/ $//;$k =~ s/ /\-/g;$e->{$k} = $v;}
        $ScanInfo_worksheet->write($ScanInfo_ctr, 0, $e->{file},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 1, $e->{"host-ip"},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 2, $e->{name},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 3, $e->{"operating-system"},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 4, $e->{"system-type"},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 5, $e->{HOST_START},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 6, $e->{HOST_END},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 7, $e->{'po-Scan-duration'},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 8, $e->{'po-Experimental-tests'},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 9, $e->{'po-Credentialed-checks'},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 10, $e->{'po-Patch-management-checks'},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 11, $e->{'po-Safe-checks'},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 12, $e->{'po-CGI-scanning'},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 13, $e->{'po-Web-application-tests'},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 14, $e->{'po-Paranoia-level'},$cell_format);
        $ScanInfo_worksheet->write($ScanInfo_ctr, 15, $e->{'po-Thorough-tests'},$cell_format);
        ++$ScanInfo_ctr;
    }
    ## end of foreach my $e (@ScanInfo)
}
### end of ScanInfo

my $cvss_total_score_ctr = 5;
print "Storing CVSS Total Score Data Table\n";
my $cvss_total_score_worksheet = $workbook->add_worksheet('CVSS Score Total');
$cvss_total_score_worksheet->write_url( 'A1', $home_url, $url_format, $_);
$cvss_total_score_worksheet->keep_leading_zeros();
$cvss_total_score_worksheet->write(4, 0, 'Host IP Address',$center_border6_format);
$cvss_total_score_worksheet->write(4, 1, 'Total',$center_border6_format);
$cvss_total_score_worksheet->write(4, 2, 'Base Total',$center_border6_format);
$cvss_total_score_worksheet->write(4, 3, 'Temporal Total',$center_border6_format);
$cvss_total_score_worksheet->write(4, 4, 'Base Critical Severity (4)',$center_border6_format);
$cvss_total_score_worksheet->write(4, 5, 'Temporal Critical Severity (4)',$center_border6_format);
$cvss_total_score_worksheet->write(4, 6, 'Base High Severity (3)',$center_border6_format);
$cvss_total_score_worksheet->write(4, 7, 'Temporal High Severity (3)',$center_border6_format);
$cvss_total_score_worksheet->write(4, 8, 'Base Medium Severity (2)',$center_border6_format);
$cvss_total_score_worksheet->write(4, 9, 'Temporal Medium Severity (2)',$center_border6_format);
$cvss_total_score_worksheet->write(1, 1, 'Critical',$center_border6_format);
$cvss_total_score_worksheet->write(1, 2, 'High',$center_border6_format);
$cvss_total_score_worksheet->write(1, 3, 'Medium',$center_border6_format);
$cvss_total_score_worksheet->write(2, 0, 'Multiplier',$center_border6_format);
$cvss_total_score_worksheet->write(2, 1, '1',$cell_format);
$cvss_total_score_worksheet->write(2, 2, '1',$cell_format);
$cvss_total_score_worksheet->write(2, 3, '1',$cell_format);
$cvss_total_score_worksheet->freeze_panes('E6');
$cvss_total_score_worksheet->autofilter('A5:T5');
$cvss_total_score_worksheet->set_column('A:J', 20);

foreach (keys %cvss_score){
    my $formulia_cnt = $cvss_total_score_ctr + 1;
    my $total_sum = "\=C$formulia_cnt\+D$formulia_cnt";
    my $base_sum = "\=\(\$B\$3\*E$formulia_cnt\)\+\(\$C\$3\*G$formulia_cnt\)\+\(\$D\$3\*I$formulia_cnt\)";
    my $temporal_sum ="\=\(\$B\$3\*F$formulia_cnt\)\+\(\$C\$3\*H$formulia_cnt\)\+\(\$D\$3\*J$formulia_cnt\)";
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 0, $_,$cell_format);
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 1, $total_sum,$cell_format);
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 2, $base_sum,$cell_format);
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 3, $temporal_sum,$cell_format);
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 4, $cvss_score{$_}->{critical_base_score},$cell_format);
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 5, $cvss_score{$_}->{critical_temporal_score},$cell_format);
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 6, $cvss_score{$_}->{high_base_score},$cell_format);
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 7, $cvss_score{$_}->{high_temporal_score},$cell_format);
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 8, $cvss_score{$_}->{med_base_score},$cell_format);
    $cvss_total_score_worksheet->write($cvss_total_score_ctr, 9, $cvss_score{$_}->{med_temporal_score},$cell_format);
    ++$cvss_total_score_ctr;
}
# end foreach (keys %cvss_score)

if($vulnerability_data{criticalvuln}->[0] ne ""){
    my $vuln_type = "criticalvuln";
    my $criticalvulns_worksheet = $workbook->add_worksheet('Critical');
    $criticalvulns_worksheet->set_tab_color('red');
    print "Storing $vuln_type Vulnerabilities Table\n";
    $criticalvulns_worksheet = vulnerability_plugin_worksheet($vuln_type,$criticalvulns_worksheet);
}
## end of Critical

if($vulnerability_data{highvuln}->[0] ne ""){
    my $vuln_type = "highvuln";
    my $highvulns_worksheet = $workbook->add_worksheet('High');
    $highvulns_worksheet->set_tab_color('orange');
    print "Storing $vuln_type Vulnerabilities Table\n";
    $highvulns_worksheet = vulnerability_plugin_worksheet($vuln_type,$highvulns_worksheet);
}
## end of Critical

if($vulnerability_data{medvuln}->[0] ne ""){
    my $vuln_type = "medvuln";
    my $medvulns_worksheet = $workbook->add_worksheet('Medium');
    $medvulns_worksheet->set_tab_color('yellow');
    print "Storing $vuln_type Vulnerabilities Table\n";
    $medvulns_worksheet = vulnerability_plugin_worksheet($vuln_type,$medvulns_worksheet);
}
## end of Critical

if($vulnerability_data{lowvuln}->[0] ne ""){
    my $vuln_type = "lowvuln";
    my $lowvulns_worksheet = $workbook->add_worksheet('low');
    $lowvulns_worksheet->set_tab_color('green');
    print "Storing $vuln_type Vulnerabilities Table\n";
    $lowvulns_worksheet = vulnerability_plugin_worksheet($vuln_type,$lowvulns_worksheet);
}
## end of Critical

if($vulnerability_data{nonevuln}->[0] ne ""){
    my $vuln_type = "nonevuln";
    my $nonevulns_worksheet = $workbook->add_worksheet('Information');
    $nonevulns_worksheet->set_tab_color('blue');
    print "Storing $vuln_type Vulnerabilities Table\n";
    $nonevulns_worksheet = vulnerability_plugin_worksheet($vuln_type,$nonevulns_worksheet);
}
## end of Critical

my $CPE_ReportData_ctr = 2;
print "Storing CPE_ReportData Table\n";
my $CPE_ReportData_worksheet = $workbook->add_worksheet('CPE Report Data');
$CPE_ReportData_worksheet->write_url( 'A1', $home_url, $url_format, $_);
$CPE_ReportData_worksheet->keep_leading_zeros();
$CPE_ReportData_worksheet->write(1, 0, 'File',$center_border6_format);
$CPE_ReportData_worksheet->write(1, 1, 'IP Address',$center_border6_format);
$CPE_ReportData_worksheet->write(1, 2, 'FQDN',$center_border6_format);
$CPE_ReportData_worksheet->write(1, 3, 'Netbios Name',$center_border6_format);
$CPE_ReportData_worksheet->write(1, 4, 'Name',$center_border6_format);
$CPE_ReportData_worksheet->write(1, 5, 'Plugin Family',$center_border6_format);
$CPE_ReportData_worksheet->write(1, 6, 'Plugin ID',$center_border6_format);
$CPE_ReportData_worksheet->write(1, 7, 'Plugin Name',$center_border6_format);
$CPE_ReportData_worksheet->write(1, 8, 'CPE',$center_border6_format);
$CPE_ReportData_worksheet->write(1, 9, 'CPE Source',$center_border6_format);

$CPE_ReportData_worksheet->freeze_panes('C3');
$CPE_ReportData_worksheet->autofilter('A2:Z2');
$CPE_ReportData_worksheet->set_column('A:Z',20);
$CPE_ReportData_worksheet->set_column('B:B',15);
$CPE_ReportData_worksheet->set_column('C:C',25);
$CPE_ReportData_worksheet->set_column('D:G',15);
$CPE_ReportData_worksheet->set_column('H:I',35);

foreach my $host (@cpe_data){
    my @tmp_cpe;
    if ($host->{cpe} =~ /\n/) {@tmp_cpe = split /\n/,$host->{cpe};}
    else{push @tmp_cpe, $host->{cpe}}
    
    foreach my $e (@tmp_cpe){
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 0, $host->{"file"},$cell_format);
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 1, $host->{"host-ip"},$cell_format);
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 2, $host->{"fqdn"},$cell_format);
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 3, $host->{"netbios-name"},$cell_format);
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 4, $host->{"name"},$cell_format);
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 5, $host->{"pluginFamily"},$cell_format);
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 6, $host->{"pluginID"},$cell_format);
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 7, $host->{"pluginName"},$cell_format);
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 8, $e,$cell_format);
        $CPE_ReportData_worksheet->write($CPE_ReportData_ctr, 9, $host->{'cpe-source'},$cell_format);
        ++$CPE_ReportData_ctr;  
    }
    # end of foreach my $e (@tmp_cpe)
}
# end foreach (@cpe_data)

my $DeviceType_Datactr = 2;
print "Storing Device Type Data Table\n";
my $DeviceType_Data_worksheet = $workbook->add_worksheet('Device Type');
$DeviceType_Data_worksheet->write_url( 'A1', $home_url, $url_format, $_);
$DeviceType_Data_worksheet->keep_leading_zeros();
$DeviceType_Data_worksheet->write(1, 0, 'File',$center_border6_format);
$DeviceType_Data_worksheet->write(1, 1, 'IP Address',$center_border6_format);
$DeviceType_Data_worksheet->write(1, 2, 'FQDN',$center_border6_format);
$DeviceType_Data_worksheet->write(1, 3, 'Netbios Name',$center_border6_format);
$DeviceType_Data_worksheet->write(1, 4, 'Name',$center_border6_format);
$DeviceType_Data_worksheet->write(1, 5, 'Device Type',$center_border6_format);
$DeviceType_Data_worksheet->write(1, 6, 'Confidence Level',$center_border6_format);

$DeviceType_Data_worksheet->freeze_panes('C3');
$DeviceType_Data_worksheet->autofilter('A2:Z2');
$DeviceType_Data_worksheet->set_column('A:Z',20);
$DeviceType_Data_worksheet->set_column('B:B',15);
$DeviceType_Data_worksheet->set_column('C:C',25);
$DeviceType_Data_worksheet->set_column('D:G',15);
$DeviceType_Data_worksheet->set_column('H:I',35);

foreach my $host (@DeviceType){
    $DeviceType_Data_worksheet->write($DeviceType_Datactr, 0, $host->{"file"},$cell_format);
    $DeviceType_Data_worksheet->write($DeviceType_Datactr, 1, $host->{"host-ip"},$cell_format);
    $DeviceType_Data_worksheet->write($DeviceType_Datactr, 2, $host->{"fqdn"},$cell_format);
    $DeviceType_Data_worksheet->write($DeviceType_Datactr, 3, $host->{"netbios-name"},$cell_format);
    $DeviceType_Data_worksheet->write($DeviceType_Datactr, 4, $host->{"name"},$cell_format);
    $DeviceType_Data_worksheet->write($DeviceType_Datactr, 5, $host->{type},$cell_format);
    $DeviceType_Data_worksheet->write($DeviceType_Datactr, 6, $host->{confidenceLevel},$cell_format);
    ++$DeviceType_Datactr;  
}
# end foreach (@ DeviceType)

my $HostConfigData_ctr = 2;
print "Storing HostConfigData Table\n";
my $HostConfigData_worksheet = $workbook->add_worksheet('HostConfigData');
$HostConfigData_worksheet->write_url( 'A1', $home_url, $url_format, $_);
$HostConfigData_worksheet->keep_leading_zeros();
$HostConfigData_worksheet->write(1, 0, 'File',$center_border6_format);
$HostConfigData_worksheet->write(1, 1, 'IP Address',$center_border6_format);
$HostConfigData_worksheet->write(1, 2, 'FQDN',$center_border6_format);
$HostConfigData_worksheet->write(1, 3, 'Netbios Name',$center_border6_format);
$HostConfigData_worksheet->write(1, 4, 'OS',$center_border6_format);
$HostConfigData_worksheet->write(1, 5, 'Local Check Protocol',$center_border6_format);
$HostConfigData_worksheet->write(1, 6, 'MAC Address',$center_border6_format);
$HostConfigData_worksheet->write(1, 7, 'IP / Name',$center_border6_format);
$HostConfigData_worksheet->write(1, 8, 'Severity None (0)',$center_border6_format);
$HostConfigData_worksheet->write(1, 9, 'Severity Low (1)',$center_border6_format);
$HostConfigData_worksheet->write(1, 10, 'Severity Medium (2)',$center_border6_format);
$HostConfigData_worksheet->write(1, 11, 'Severity High (3)',$center_border6_format);
$HostConfigData_worksheet->write(1, 12, 'Severity Critical (4)',$center_border6_format);
$HostConfigData_worksheet->write(1, 13, 'Minimum password len',$center_border6_format);
$HostConfigData_worksheet->write(1, 14, 'Password history len',$center_border6_format);
$HostConfigData_worksheet->write(1, 15, 'Maximum password age days',$center_border6_format);
$HostConfigData_worksheet->write(1, 16, 'Password must meet complexity requirements',$center_border6_format);
$HostConfigData_worksheet->write(1, 17, 'Minimum password age days',$center_border6_format);
$HostConfigData_worksheet->write(1, 18, 'Forced logoff time Seconds',$center_border6_format);
$HostConfigData_worksheet->write(1, 19, 'Locked account time seconds',$center_border6_format);
$HostConfigData_worksheet->write(1, 20, 'Time between failed logon seconds',$center_border6_format);
$HostConfigData_worksheet->write(1, 21, 'Number of invalid logon before locked out seconds',$center_border6_format);
$HostConfigData_worksheet->freeze_panes('C3');
$HostConfigData_worksheet->autofilter('A2:Z2');
$HostConfigData_worksheet->set_column('A:Z',20);
$HostConfigData_worksheet->set_column('B:B',15);
$HostConfigData_worksheet->set_column('C:C',25);
$HostConfigData_worksheet->set_column('D:D',15);
$HostConfigData_worksheet->set_column('E:H',15);

foreach my $host (@host_data){
    $HostConfigData_worksheet->write($HostConfigData_ctr, 0, $host->{"file"},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 1, $host->{"host-ip"},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 2, $host->{"host-fqdn"},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 3, $host->{"netbios-name"},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 4, $host->{"operating-system"},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 5, $host->{"local-checks-proto"},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 6, $host->{"mac-address"},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 7, $host->{"name"},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 8, $host->{vuln_cnt}->{sev0},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 9, $host->{vuln_cnt}->{sev1},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 10, $host->{vuln_cnt}->{sev2},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 11, $host->{vuln_cnt}->{sev3},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 12, $host->{vuln_cnt}->{sev4},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 13, $host->{'Minimum password len'},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 14, $host->{'Password history len'},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 15, $host->{'Maximum password age (d)'},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 16, $host->{'Password must meet complexity requirements'},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 17, $host->{'Minimum password age (d)'},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 18, $host->{'Forced logoff time (s)'},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 19, $host->{'Locked account time (s)'},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 20, $host->{'Time between failed logon (s)'},$cell_format);
    $HostConfigData_worksheet->write($HostConfigData_ctr, 21, $host->{'Number of invalid logon before locked out (s)'},$cell_format);
    ++$HostConfigData_ctr;
}
# end foreach (@HostConfigData)

if ($portScanner[0] ne "") {
    my $portScanData_ctr = 2;
    print "Storing portScanData Table\n";
    my $portScanData_worksheet = $workbook->add_worksheet('portScanData');
    $portScanData_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $portScanData_worksheet->keep_leading_zeros();
    $portScanData_worksheet->write(1, 0, 'File',$center_border6_format);
    $portScanData_worksheet->write(1, 1, 'IP Address',$center_border6_format);
    $portScanData_worksheet->write(1, 2, 'FQDN',$center_border6_format);
    $portScanData_worksheet->write(1, 3, 'Netbios Name',$center_border6_format);
    $portScanData_worksheet->write(1, 4, 'OS',$center_border6_format);
    $portScanData_worksheet->write(1, 5, 'Plugin Name',$center_border6_format);
    $portScanData_worksheet->write(1, 6, 'Protocol',$center_border6_format);
    $portScanData_worksheet->write(1, 7, 'Port',$center_border6_format);
    $portScanData_worksheet->write(1, 8, 'Sevice Name',$center_border6_format);
    $portScanData_worksheet->write(1, 9, 'Plugin Output',$center_border6_format);
    $portScanData_worksheet->write(1, 10, 'DELETE',$center_border6_format);
    $portScanData_worksheet->freeze_panes('C3');
    $portScanData_worksheet->autofilter('A2:K2');
    $portScanData_worksheet->set_column('A:Z',20);
    
    foreach my $host (@portScanner){
        $portScanData_worksheet->write($portScanData_ctr, 0, $host->{"file"},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 1, $host->{"name"},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 2, $host->{"fqdn"},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 3, $host->{"netbios_name"},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 4, $host->{"operating_system"},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 5, $host->{vuln}->{-pluginName},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 6, $host->{vuln}->{-protocol},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 7, $host->{vuln}->{-port},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 8, $host->{vuln}->{-svc_name},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 9, $host->{vuln}->{plugin_output},$cell_format);
        $portScanData_worksheet->write($portScanData_ctr, 10, $host->{vuln}->{-pluginFamily},$cell_format);
        ++$portScanData_ctr;
    }
    # end foreach (@portScanData)
}
# end of if ($portScanner[0] ne "")

if ($installedSoftware[0] ne "") {
    my $InstalledSoftwareData_ctr = 2;
    print "Storing InstalledSoftwareData Table\n";
    my $InstalledSoftwareData_worksheet = $workbook->add_worksheet('InstalledSoftwareData');
    $InstalledSoftwareData_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $InstalledSoftwareData_worksheet->keep_leading_zeros();
    $InstalledSoftwareData_worksheet->write(1,  0, 'File',$center_border6_format);
    $InstalledSoftwareData_worksheet->write(1,  1, 'IP Address',$center_border6_format);
    $InstalledSoftwareData_worksheet->write(1,  2, 'FQDN',$center_border6_format);
    $InstalledSoftwareData_worksheet->write(1,  3, 'Netbios Name',$center_border6_format);
    $InstalledSoftwareData_worksheet->write(1,  4, 'Operating System',$center_border6_format);
    $InstalledSoftwareData_worksheet->write(1,  5, 'Plugin ID',$center_border6_format);
    $InstalledSoftwareData_worksheet->write(1,  6, 'Plugin Name',$center_border6_format);
    $InstalledSoftwareData_worksheet->write(1,  7, 'Software',$center_border6_format);
    $InstalledSoftwareData_worksheet->freeze_panes('C3');
    $InstalledSoftwareData_worksheet->autofilter('A2:H2');
    $InstalledSoftwareData_worksheet->set_column('A:Z',20);
    $InstalledSoftwareData_worksheet->set_column('B:B',15);
    $InstalledSoftwareData_worksheet->set_column('C:C',25);
    $InstalledSoftwareData_worksheet->set_column('D:D',15);
    $InstalledSoftwareData_worksheet->set_column('E:E',15);
    $InstalledSoftwareData_worksheet->set_column('H:H',60);
    
    foreach my $host (@installedSoftware){
        my $software;
        my @t1 = split /\|\|/, $host->{vuln}->{plugin_output};
        my @t3;
        my @t2 = split /\|/, $t1[1];
        foreach (@t2){$_ =~ s/^\s+//}
        my $cnt = @t2;
        --$cnt;
        while ($cnt > 0) {
            my $s = "$t2[$cnt-1] $t2[$cnt]";
            push @t3, $s;
            $cnt = $cnt-2;
        }
        $software = join ";", @t3;
        
        $InstalledSoftwareData_worksheet->write($InstalledSoftwareData_ctr, 0,  $host->{file},$cell_format);
        $InstalledSoftwareData_worksheet->write($InstalledSoftwareData_ctr, 1,  $host->{name},$cell_format);
        $InstalledSoftwareData_worksheet->write($InstalledSoftwareData_ctr, 2,  $host->{fqdn},$cell_format);
        $InstalledSoftwareData_worksheet->write($InstalledSoftwareData_ctr, 3,  $host->{netbios_name},$cell_format);
        $InstalledSoftwareData_worksheet->write($InstalledSoftwareData_ctr, 4,  $host->{operating_system},$cell_format);
        $InstalledSoftwareData_worksheet->write($InstalledSoftwareData_ctr, 5,  $host->{vuln}->{-pluginID},$cell_format);
        $InstalledSoftwareData_worksheet->write($InstalledSoftwareData_ctr, 6,  $host->{vuln}->{-pluginName},$cell_format);
        $InstalledSoftwareData_worksheet->write($InstalledSoftwareData_ctr, 7,  $software,$cell_format);
        ++$InstalledSoftwareData_ctr;
    }
    # end foreach (@InstalledSoftwareData)
}


#####################################  BEGIN OF COMPLIANCE TESTING

foreach my $c (keys %complaince){
    print "Storing $c Table\n";
    my $result = compliance_worksheet($c);
}
# end of foreach my $keys (%complaince)

#####################################  END OF COMPLIANCE TESTING

if($PCIDSS[0] ne "") {
    print "Storing PCI DSS Table\n";
    my $PCIDSS_ctr = 2;
    our $PCIDSS_worksheet = $workbook->add_worksheet('PCIDSSPolicy');
    $PCIDSS_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $PCIDSS_worksheet->keep_leading_zeros();
    $PCIDSS_worksheet->write(1, 0, 'File',$center_border6_format);
    $PCIDSS_worksheet->write(1, 1, 'IP Address',$center_border6_format);
    $PCIDSS_worksheet->write(1, 2, 'FQDN',$center_border6_format);
    $PCIDSS_worksheet->write(1, 3, 'PluginID',$center_border6_format);
    $PCIDSS_worksheet->write(1, 4, 'protocol',$center_border6_format);
    $PCIDSS_worksheet->write(1, 5, 'severity',$center_border6_format);
    $PCIDSS_worksheet->write(1, 6, 'pluginFamily',$center_border6_format);
    $PCIDSS_worksheet->write(1, 7, 'plugin Type',$center_border6_format);
    $PCIDSS_worksheet->write(1, 8, 'Synopsis',$center_border6_format);
    $PCIDSS_worksheet->write(1, 9, 'Plugin Output',$center_border6_format);
    $PCIDSS_worksheet->write(1, 10, 'See Also',$center_border6_format);
    $PCIDSS_worksheet->set_tab_color('blue');
    $PCIDSS_worksheet->freeze_panes('C3');
    $PCIDSS_worksheet->autofilter('A2:K2');
    $PCIDSS_worksheet->set_column('A:K', 20);
    foreach (@PCIDSS){
        $PCIDSS_worksheet->write($PCIDSS_ctr, 0, $_->{'file'},$cell_format);
        $PCIDSS_worksheet->write($PCIDSS_ctr, 1, $_->{'name'},$cell_format);
        $PCIDSS_worksheet->write($PCIDSS_ctr, 2, $_->{'fqdn'},$cell_format);
        $PCIDSS_worksheet->write($PCIDSS_ctr, 3, $_->{vuln}->{-pluginID},$cell_format);#PluginID
        $PCIDSS_worksheet->write($PCIDSS_ctr, 4, $_->{vuln}->{-protocol},$cell_format);#protocol
        $PCIDSS_worksheet->write($PCIDSS_ctr, 5, $_->{vuln}->{-severity},$cell_format);#severity
        $PCIDSS_worksheet->write($PCIDSS_ctr, 6, $_->{vuln}->{-pluginFamily},$cell_format);#pluginFamily
        $PCIDSS_worksheet->write($PCIDSS_ctr, 7, $_->{vuln}->{plugin_type},$cell_format);
        $PCIDSS_worksheet->write($PCIDSS_ctr, 8, $_->{vuln}->{synopsis},$cell_format);
        $PCIDSS_worksheet->write($PCIDSS_ctr, 9, $_->{vuln}->{plugin_output},$cell_format);
        $PCIDSS_worksheet->write($PCIDSS_ctr, 10, " $_->{vuln}->{see_also}",$cell_format);
        ++$PCIDSS_ctr;
    }
    # end foreach (@PCIDSS)
}
# end of @PCIDSS

if($WirelessAccessPointDetection[0] ne ""){
    print "Storing WirelessAccessPointDetection Table\n";
    my $WirelessAccessPointDetection_ctr = 2;
    our $WirelessAccessPointDetection_worksheet = $workbook->add_worksheet('WAP Detection Policy');
    $WirelessAccessPointDetection_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $WirelessAccessPointDetection_worksheet->keep_leading_zeros();
    $WirelessAccessPointDetection_worksheet->write(1, 0, 'Name',$center_border6_format);
    $WirelessAccessPointDetection_worksheet->write(1, 1, 'IP Address',$center_border6_format);
    $WirelessAccessPointDetection_worksheet->write(1, 2, 'FQDN',$center_border6_format);
    $WirelessAccessPointDetection_worksheet->write(1, 3, 'Operating System',$center_border6_format);
    $WirelessAccessPointDetection_worksheet->write(1, 4, 'MAC Address',$center_border6_format);
    $WirelessAccessPointDetection_worksheet->write(1, 5, 'System Type',$center_border6_format);
    $WirelessAccessPointDetection_worksheet->write(1, 6, 'Plugin Output',$center_border6_format);
    $WirelessAccessPointDetection_worksheet->freeze_panes('C3');
    $WirelessAccessPointDetection_worksheet->autofilter('A2:K2');
    $WirelessAccessPointDetection_worksheet->set_column('A:M', 20);
    foreach (@WirelessAccessPointDetection){
        $WirelessAccessPointDetection_worksheet->write($WirelessAccessPointDetection_ctr, 0, $_->{'name'},$cell_format);
        $WirelessAccessPointDetection_worksheet->write($WirelessAccessPointDetection_ctr, 1, $_->{'host-ip'},$cell_format);
        $WirelessAccessPointDetection_worksheet->write($WirelessAccessPointDetection_ctr, 2, $_->{'host-fqdn'},$cell_format);
        $WirelessAccessPointDetection_worksheet->write($WirelessAccessPointDetection_ctr, 3, $_->{'operating-system'},$cell_format);
        $WirelessAccessPointDetection_worksheet->write($WirelessAccessPointDetection_ctr, 4, $_->{"mac-address"},$cell_format);
        $WirelessAccessPointDetection_worksheet->write($WirelessAccessPointDetection_ctr, 5, $_->{'system-type'},$cell_format);
        $WirelessAccessPointDetection_worksheet->write($WirelessAccessPointDetection_ctr, 6, $_->{"plugin-output"},$cell_format);
        ++$WirelessAccessPointDetection_ctr;
    }
    # end foreach (@WirelessAccessPointDetection)
}
# end of @WirelessAccessPointDetection

if($WinWirelessSSID[0] ne ""){
    print "Storing WinWirelessSSID Table\n";
    my $WinWirelessSSID_ctr = 2;
    my $WinWirelessSSID_worksheet = $workbook->add_worksheet('Wireless SSID Detection Policy');
    $WinWirelessSSID_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $WinWirelessSSID_worksheet->keep_leading_zeros();
    $WinWirelessSSID_worksheet->write(1, 0, 'Name',$center_border6_format);
    $WinWirelessSSID_worksheet->write(1, 1, 'IP Address',$center_border6_format);
    $WinWirelessSSID_worksheet->write(1, 2, 'FQDN',$center_border6_format);
    $WinWirelessSSID_worksheet->write(1, 3, 'Operating System',$center_border6_format);
    $WinWirelessSSID_worksheet->write(1, 4, 'MAC Address',$center_border6_format);
    $WinWirelessSSID_worksheet->write(1, 5, 'System Type',$center_border6_format);
    $WinWirelessSSID_worksheet->write(1, 6, 'Network Interface Card',$center_border6_format);
    $WinWirelessSSID_worksheet->write(1, 7, 'Network SSID',$center_border6_format);
    $WinWirelessSSID_worksheet->freeze_panes('C3');
    $WinWirelessSSID_worksheet->autofilter('A2:K2');
    $WinWirelessSSID_worksheet->set_column('A:M', 20);
    foreach (@WinWirelessSSID){
        $WinWirelessSSID_worksheet->write($WinWirelessSSID_ctr, 0, $_->{'name'},$cell_format);
        $WinWirelessSSID_worksheet->write($WinWirelessSSID_ctr, 1, $_->{'host-ip'},$cell_format);
        $WinWirelessSSID_worksheet->write($WinWirelessSSID_ctr, 2, $_->{'host-fqdn'},$cell_format);
        $WinWirelessSSID_worksheet->write($WinWirelessSSID_ctr, 3, $_->{'operating-system'},$cell_format);
        $WinWirelessSSID_worksheet->write($WinWirelessSSID_ctr, 4, $_->{"mac-address"},$cell_format);
        $WinWirelessSSID_worksheet->write($WinWirelessSSID_ctr, 5, $_->{'system-type'},$cell_format);
        $WinWirelessSSID_worksheet->write($WinWirelessSSID_ctr, 6, $_->{"nic"},$cell_format);
        $WinWirelessSSID_worksheet->write($WinWirelessSSID_ctr, 7, $_->{"ssid"},$cell_format);
        ++$WinWirelessSSID_ctr;
    }
    # end foreach (@WinWirelessSSID)
}
# end of @WinWirelessSSID

if($EnumLocalGrp[0] ne "") {
    my $EnumLocalGrpctr = 2;
    print "Storing EnumLocalGrp Data Table\n";
    my $EnumLocalGrpworksheet = $workbook->add_worksheet('EnumLocalGrp');
    $EnumLocalGrpworksheet->write_url( 'A1', $home_url, $url_format, $_);
    $EnumLocalGrpworksheet->keep_leading_zeros();
    $EnumLocalGrpworksheet->write(1,  0, 'File',$center_border6_format);
    $EnumLocalGrpworksheet->write(1,  1, 'IP Address',$center_border6_format);
    $EnumLocalGrpworksheet->write(1,  2, 'FQDN',$center_border6_format);
    $EnumLocalGrpworksheet->write(1,  3, 'Netbios Name',$center_border6_format);
    $EnumLocalGrpworksheet->write(1,  4, "Group Name",$center_border6_format);
    $EnumLocalGrpworksheet->write(1,  5, "Group SID",$center_border6_format);
    $EnumLocalGrpworksheet->write(1,  6, "Member Count",$center_border6_format);
    $EnumLocalGrpworksheet->write(1,  7, "Class",$center_border6_format);
    $EnumLocalGrpworksheet->write(1,  8, "Domain",$center_border6_format);
    $EnumLocalGrpworksheet->write(1,  9, "Username",$center_border6_format);
    $EnumLocalGrpworksheet->write(1, 10, "User SID",$center_border6_format);
    $EnumLocalGrpworksheet->freeze_panes('C3');
    $EnumLocalGrpworksheet->autofilter('A2:J2');
    $EnumLocalGrpworksheet->set_column('A:Z',20);
    $EnumLocalGrpworksheet->set_column('B:B',15);
    $EnumLocalGrpworksheet->set_column('C:J',25);
    
    foreach my $host (@EnumLocalGrp){
        foreach my $grp (@{$host->{groups}}){
            if (ref $grp->{members}->[0] eq "HASH") {
                my $member_cnt = @{$grp->{members}};
                foreach my $m (@{$grp->{members}}){
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 0,  $host->{"file"},$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 1,  $host->{"host-ip"},$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 2,  $host->{"fqdn"},$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 3,  $host->{"netbios-name"},$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 4,  $grp->{'Group Name'},$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 5,  $grp->{'Group SID'},$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 6,  $member_cnt,$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 7,  $m->{Class},$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 8,  $m->{Domain},$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 9,  $m->{Name},$cell_format);
                    $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 10, $m->{SID},$cell_format);
                    ++$EnumLocalGrpctr;
                }
                # end of foreach my $m (@{$grp->{members}})
            }
            else{
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 0,  $host->{"file"},$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 1,  $host->{"host-ip"},$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 2,  $host->{"fqdn"},$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 3,  $host->{"netbios-name"},$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 4,  $grp->{'Group Name'},$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 5,  $grp->{'Group SID'},$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 6,  '0',$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 7,  '',$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 8,  '',$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 9,  '',$cell_format);
                $EnumLocalGrpworksheet->write($EnumLocalGrpctr, 10, '',$cell_format);
                ++$EnumLocalGrpctr;
            }
            # end if..else
        }
        # end of foreach my $grp (@{$host->{groups}})
    }
    # end foreach (@EnumLocalGrp)
}
# end @EnumLocalGrp

if($MS_Process_Info[0] ne ""){
    my $MS_Process_Info_ctr = 2;
    print "Storing MS Running Process Info Table\n";
    my $MS_Process_Info_worksheet = $workbook->add_worksheet('MS Running Process Info');
    $MS_Process_Info_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $MS_Process_Info_worksheet->keep_leading_zeros();
    $MS_Process_Info_worksheet->write(1,  0, "Index",$center_border6_format);
    $MS_Process_Info_worksheet->write(1,  1, 'File',$center_border6_format);
    $MS_Process_Info_worksheet->write(1,  2, 'IP Address',$center_border6_format);
    $MS_Process_Info_worksheet->write(1,  3, 'FQDN',$center_border6_format);
    $MS_Process_Info_worksheet->write(1,  4, 'Netbios Name',$center_border6_format);
    $MS_Process_Info_worksheet->write(1,  5, "Process Name & Level",$center_border6_format);
    $MS_Process_Info_worksheet->freeze_panes('C3');
    $MS_Process_Info_worksheet->autofilter('A2:E2');
    $MS_Process_Info_worksheet->set_column('A:A',10);
    $MS_Process_Info_worksheet->set_column('B:B',25);
    $MS_Process_Info_worksheet->set_column('D:D',25);
    $MS_Process_Info_worksheet->set_column('E:E',15);
    $MS_Process_Info_worksheet->set_column('F:F',80);
    
    foreach my $host (@MS_Process_Info){
        foreach my $p (@{$host->{processes}}){
            $MS_Process_Info_worksheet->write($MS_Process_Info_ctr, 0,  $MS_Process_Info_ctr - 2,$cell_format);
            $MS_Process_Info_worksheet->write($MS_Process_Info_ctr, 1,  $host->{"file"},$cell_format);
            $MS_Process_Info_worksheet->write($MS_Process_Info_ctr, 2,  $host->{"host-ip"},$cell_format);
            $MS_Process_Info_worksheet->write($MS_Process_Info_ctr, 3,  $host->{"fqdn"},$cell_format);
            $MS_Process_Info_worksheet->write($MS_Process_Info_ctr, 4,  $host->{"netbios-name"},$cell_format);
            $MS_Process_Info_worksheet->write($MS_Process_Info_ctr, 5,  $p,$cell_format);
            ++$MS_Process_Info_ctr;
        }
        # end of foreach my $p (@{$host->{processes}})
    }
    # end foreach (@MS_Process_Info)
}
# end of @MS_Process_Info

if(keys %ms_process_cnt > 0){
    my $ms_process_cnt_ctr = 2;
    print "Storing MS Process Count Table\n";
    my $ms_process_cnt_worksheet = $workbook->add_worksheet('MS Process Count');
    $ms_process_cnt_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $ms_process_cnt_worksheet->keep_leading_zeros();
    $ms_process_cnt_worksheet->write(1,  0, 'Process Name',$center_border6_format);
    $ms_process_cnt_worksheet->write(1,  1, 'Total Count',$center_border6_format);
    $ms_process_cnt_worksheet->write(1,  2, 'IP address',$center_border6_format);
    $ms_process_cnt_worksheet->write(1,  3, 'Count Per IP',$center_border6_format);
    $ms_process_cnt_worksheet->freeze_panes('C3');
    $ms_process_cnt_worksheet->autofilter('A2:D2');
    $ms_process_cnt_worksheet->set_column('A:Z',20);
    $ms_process_cnt_worksheet->set_column('B:B',15);
    $ms_process_cnt_worksheet->set_column('C:C',25);
    $ms_process_cnt_worksheet->set_column('D:D',15);
    
    foreach my $process (keys %ms_process_cnt){
        my $total_process_cnt = 0;
        foreach my $ip (values %{$ms_process_cnt{$process}}){$total_process_cnt = $total_process_cnt + $ip;}
        foreach my $ip (keys %{$ms_process_cnt{$process}}){
            $ms_process_cnt_worksheet->write($ms_process_cnt_ctr, 0,  $process,$cell_format);
            $ms_process_cnt_worksheet->write($ms_process_cnt_ctr, 1,  $total_process_cnt,$cell_format);
            $ms_process_cnt_worksheet->write($ms_process_cnt_ctr, 2,  $ip,$cell_format);
            $ms_process_cnt_worksheet->write($ms_process_cnt_ctr, 3,  $ms_process_cnt{$process}->{$ip},$cell_format);
            ++$ms_process_cnt_ctr;
        }
        # end of foreach my $ip (keys %{$ms_process_cnt{$process}})
    }
    # end foreach (@ms_process_cnt)
}
# end of %ms_process_cnt

my $UserAccountData_ctr = 2;
print "Storing UserAccountData Table\n";
my $UserAccountData_worksheet = $workbook->add_worksheet('UserAccountData');
$UserAccountData_worksheet->write_url( 'A1', $home_url, $url_format, $_);
$UserAccountData_worksheet->keep_leading_zeros();
$UserAccountData_worksheet->write(1, 0, 'User Location',$center_border6_format);
$UserAccountData_worksheet->write(1, 1, 'Name',$center_border6_format);
$UserAccountData_worksheet->write(1, 2, 'SID',$center_border6_format);
$UserAccountData_worksheet->write(1, 3, 'type',$center_border6_format);
$UserAccountData_worksheet->write(1, 4, 'Never Changed Password',$center_border6_format);
$UserAccountData_worksheet->write(1, 5, 'Automatic Account Disabled',$center_border6_format);
$UserAccountData_worksheet->write(1, 6, 'Account Disabled',$center_border6_format);
$UserAccountData_worksheet->write(1, 7, 'Never Changed Password',$center_border6_format);
$UserAccountData_worksheet->write(1, 8, 'Never Logged In',$center_border6_format);
$UserAccountData_worksheet->write(1, 9, 'Guest Account Belongs to a Group',$center_border6_format);
$UserAccountData_worksheet->write(1, 10, 'Administrators',$center_border6_format);
$UserAccountData_worksheet->write(1, 11, 'Domain Administrators',$center_border6_format);
$UserAccountData_worksheet->write(1, 12, 'Account Operators',$center_border6_format);
$UserAccountData_worksheet->write(1, 13, 'Server Operators',$center_border6_format);
$UserAccountData_worksheet->write(1, 14, 'Backup Operators',$center_border6_format);
$UserAccountData_worksheet->write(1, 15, 'Print Operators',$center_border6_format);
$UserAccountData_worksheet->write(1, 16, 'Replicator',$center_border6_format);
$UserAccountData_worksheet->freeze_panes('C3');
$UserAccountData_worksheet->autofilter('A2:S2');
$UserAccountData_worksheet->set_column('A:S',20);
my $host_data_cnt = 2;
foreach my $user (@ADUsers){
    $UserAccountData_worksheet->write($UserAccountData_ctr, 0, "Active Directory");
    $UserAccountData_worksheet->write($UserAccountData_ctr, 1, $user->{'name'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 2, $user->{'sid'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 3, $user->{'type'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 4, $user->{'Never Changed Password'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 5, $user->{'Automatic Account Disabled'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 6, $user->{'Account Disabled'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 7, $user->{'Never Changed Password'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 8, $user->{'Never Logged In'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 9, $user->{'Guest Account Belongs to a Group'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 10, $user->{'Administrators'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 11, $user->{'Domain Administrators'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 12, $user->{'Account Operators'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 13, $user->{'Server Operators'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 14, $user->{'Backup Operators'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 15, $user->{'Print Operators'},$cell_format);
    $UserAccountData_worksheet->write($UserAccountData_ctr, 16, $user->{'Replicator'},$cell_format);
    ++$UserAccountData_ctr;
    ++$host_data_cnt;
}
# end of foreach my $user (@ADUsers)

foreach my $host (@host_data){
    my $location = $host->{"netbios-name"};
    foreach my $user (@{$host->{account_info}}){
        $UserAccountData_worksheet->write($UserAccountData_ctr, 0, "$location",$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 1, $user->{'name'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 2, $user->{'sid'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 3, $user->{'type'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 4, $user->{'Never Changed Password'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 5, $user->{'Automatic Account Disabled'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 6, $user->{'Account Disabled'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 7, $user->{'Never Changed Password'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 8, $user->{'Never Logged In'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 9, $user->{'Guest Account Belongs to a Group'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 10, $user->{'Administrators'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 11, $user->{'Domain Administrators'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 12, $user->{'Account Operators'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 13, $user->{'Server Operators'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 14, $user->{'Backup Operators'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 15, $user->{'Print Operators'},$cell_format);
        $UserAccountData_worksheet->write($UserAccountData_ctr, 16, $user->{'Replicator'},$cell_format);
        ++$UserAccountData_ctr;
        ++$host_data_cnt;
    }
    #foreach my $user (@{$host->{account_info}})
}
# end foreach (@host_data)

print "Storing SummaryReport Table\n";
my $SummaryReport_worksheet = $workbook->add_worksheet('Summary Report Data');
$SummaryReport_worksheet->write_url( 'A1', $home_url, $url_format, $_);
$SummaryReport_worksheet->keep_leading_zeros();
$SummaryReport_worksheet->merge_range( 1, 0, 1, 3, 'User Account Sumamry', $center_border6_format );
$SummaryReport_worksheet->write(2, 1, 'User Type Count',$center_border6_format);
$SummaryReport_worksheet->write(2, 2, 'Never Changed Password',$center_border6_format);
$SummaryReport_worksheet->write(2, 3, 'Automatic Account Disabled',$center_border6_format);
$SummaryReport_worksheet->write(2, 4, 'Account Disabled',$center_border6_format);
$SummaryReport_worksheet->write(2, 5, 'Never Changed Password',$center_border6_format);
$SummaryReport_worksheet->write(2, 6, 'Never Logged In',$center_border6_format);
$SummaryReport_worksheet->write(2, 7, 'Guest Account Belongs to a Group',$center_border6_format);
$SummaryReport_worksheet->write(2, 8, 'Administrators',$center_border6_format);
$SummaryReport_worksheet->write(2, 9, 'Domain Administrators',$center_border6_format);
$SummaryReport_worksheet->write(2, 10, 'Account Operators',$center_border6_format);
$SummaryReport_worksheet->write(2, 11, 'Server Operators',$center_border6_format);
$SummaryReport_worksheet->write(2, 12, 'Backup Operators',$center_border6_format);
$SummaryReport_worksheet->write(2, 13, 'Print Operators',$center_border6_format);
$SummaryReport_worksheet->write(2, 14, 'Replicator',$center_border6_format);
$SummaryReport_worksheet->write(2, 0, '',$center_border6_format);

my $SummaryReport_cnt = 0;
$SummaryReport_worksheet->write(3, $SummaryReport_cnt, 'Domain Administrator account',$cell_format);
$SummaryReport_worksheet->write(4, $SummaryReport_cnt, 'Domain Guest account',$cell_format);
$SummaryReport_worksheet->write(5, $SummaryReport_cnt, 'Domain User',$cell_format);
$SummaryReport_worksheet->write(6, $SummaryReport_cnt, 'Administrator account',$cell_format);
$SummaryReport_worksheet->write(7, $SummaryReport_cnt, 'Guest account',$cell_format);
$SummaryReport_worksheet->write(8, $SummaryReport_cnt, 'Local User',$cell_format);
$SummaryReport_worksheet->write(9, $SummaryReport_cnt, 'Unknown',$cell_format);
$SummaryReport_worksheet->write(10, $SummaryReport_cnt, 'User',$cell_format);
$SummaryReport_worksheet->write(11, $SummaryReport_cnt, 'Group',$cell_format);
$SummaryReport_worksheet->write(12, $SummaryReport_cnt, 'Computer Account',$cell_format);
++$SummaryReport_cnt;

my $user_type = "UserAccountData!\$D\$3\:\$D\$$host_data_cnt";
$SummaryReport_worksheet->write(3, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A4\)",$cell_format);#=COUNTIF(user_type,a3)');
$SummaryReport_worksheet->write(4, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A5\)",$cell_format);
$SummaryReport_worksheet->write(5, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A6\)",$cell_format);
$SummaryReport_worksheet->write(6, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A7\)",$cell_format);
$SummaryReport_worksheet->write(7, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A8\)",$cell_format);
$SummaryReport_worksheet->write(8, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A9\)",$cell_format);
$SummaryReport_worksheet->write(9, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A10\)",$cell_format);
$SummaryReport_worksheet->write(10, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A11\)",$cell_format);
$SummaryReport_worksheet->write(11, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A12\)",$cell_format);
$SummaryReport_worksheet->write(12, $SummaryReport_cnt, "\=COUNTIF\($user_type\,A13\)",$cell_format);
++$SummaryReport_cnt;

while ($SummaryReport_cnt < 15){
    my $name_array;
    if($SummaryReport_cnt == 2){$name_array = "UserAccountData!\$E\$3\:\$E\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 3){$name_array = "UserAccountData!\$F\$3\:\$F\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 4){$name_array = "UserAccountData!\$G\$3\:\$G\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 5){$name_array = "UserAccountData!\$H\$3\:\$H\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 6){$name_array = "UserAccountData!\$I\$3\:\$I\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 7){$name_array = "UserAccountData!\$J\$3\:\$J\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 8){$name_array = "UserAccountData!\$K\$3\:\$K\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 9){$name_array = "UserAccountData!\$L\$3\:\$L\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 10){$name_array = "UserAccountData!\$M\$3\:\$M\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 11){$name_array = "UserAccountData!\$N\$3\:\$N\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 12){$name_array = "UserAccountData!\$O\$3\:\$O\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 13){$name_array = "UserAccountData!\$P\$3\:\$P\$$host_data_cnt"}# ,$cell_format}
    elsif($SummaryReport_cnt == 14){$name_array = "UserAccountData!\$Q\$3\:\$Q\$$host_data_cnt"}# ,$cell_format}
    $SummaryReport_worksheet->write(3, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A4\)\*\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    $SummaryReport_worksheet->write(4, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A5\)\,\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    $SummaryReport_worksheet->write(5, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A6\)\,\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    $SummaryReport_worksheet->write(6, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A7\)\,\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    $SummaryReport_worksheet->write(7, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A8\)\,\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    $SummaryReport_worksheet->write(8, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A9\)\,\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    $SummaryReport_worksheet->write(9, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A10\)\,\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    $SummaryReport_worksheet->write(10, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A11\)\,\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    $SummaryReport_worksheet->write(11, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A12\)\,\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    $SummaryReport_worksheet->write(12, $SummaryReport_cnt, "\=SUMPRODUCT\(\-\-\($user_type \= A13\)\,\-\-\($name_array \=\"Y\"\)\)",$cell_format);
    ++$SummaryReport_cnt;
}
# end of while ($SummaryReport_cnt < 15)

$SummaryReport_cnt = 16;
$SummaryReport_worksheet->merge_range( $SummaryReport_cnt,0, $SummaryReport_cnt, 3, 'Critical Severity Vulnerability Top 10 By Plugin Family', $center_border6_format );
++$SummaryReport_cnt;
$SummaryReport_worksheet->write($SummaryReport_cnt, 0, 'plugin Family',$center_border6_format);
$SummaryReport_worksheet->write($SummaryReport_cnt, 1, 'plugin id',$center_border6_format);
$SummaryReport_worksheet->write($SummaryReport_cnt, 2, 'plugin Name',$center_border6_format);
$SummaryReport_worksheet->write($SummaryReport_cnt, 3, 'count',$center_border6_format);
$SummaryReport_worksheet->set_column('A:M', 20);
++$SummaryReport_cnt;

# $vulnerability_data{medvuln}
my @criticalvuln_uniq_plugin_family = vuln_seperate_by_plugin(\@{$vulnerability_data{criticalvuln}});
foreach my $entry (@criticalvuln_uniq_plugin_family){
    my @tmp = @{$entry->{entries}};
    foreach my $t (@tmp){
        $SummaryReport_worksheet->write($SummaryReport_cnt, 0, $t->[5],$cell_format);
        $SummaryReport_worksheet->write($SummaryReport_cnt, 1, $t->[0],$cell_format);
        $SummaryReport_worksheet->write($SummaryReport_cnt, 2, $t->[3],$cell_format);
        $SummaryReport_worksheet->write($SummaryReport_cnt, 3, $t->[2],$cell_format);
        ++$SummaryReport_cnt;
    }
    # end of foreach my $t (@tmp)
}
# end of foreach my $entry (@criticalvuln_uniq_plugin_family)

$SummaryReport_cnt = $SummaryReport_cnt + 3;
$SummaryReport_worksheet->merge_range( $SummaryReport_cnt,0, $SummaryReport_cnt, 3, 'High Severity Vulnerability Top 10 By Plugin Family', $center_border6_format );
++$SummaryReport_cnt;
$SummaryReport_worksheet->write($SummaryReport_cnt, 0, 'plugin Family',$center_border6_format);
$SummaryReport_worksheet->write($SummaryReport_cnt, 1, 'plugin id',$center_border6_format);
$SummaryReport_worksheet->write($SummaryReport_cnt, 2, 'plugin Name',$center_border6_format);
$SummaryReport_worksheet->write($SummaryReport_cnt, 3, 'count',$center_border6_format);
$SummaryReport_worksheet->set_column('A:M', 20);
++$SummaryReport_cnt;
my @highvuln_uniq_plugin_family = vuln_seperate_by_plugin(\@{$vulnerability_data{highvuln}});
foreach my $entry (@highvuln_uniq_plugin_family){
    my @tmp = @{$entry->{entries}};
    foreach my $t (@tmp){
        $SummaryReport_worksheet->write($SummaryReport_cnt, 0, $t->[5],$cell_format);
        $SummaryReport_worksheet->write($SummaryReport_cnt, 1, $t->[0],$cell_format);
        $SummaryReport_worksheet->write($SummaryReport_cnt, 2, $t->[3],$cell_format);
        $SummaryReport_worksheet->write($SummaryReport_cnt, 3, $t->[2],$cell_format);
        ++$SummaryReport_cnt;
    }
    # end of @foreach my $t (@tmp)
}
# end of foreach my $entry (@highvuln_uniq_plugin_family)

$SummaryReport_cnt = $SummaryReport_cnt + 3;
$SummaryReport_worksheet->merge_range( $SummaryReport_cnt,0, $SummaryReport_cnt, 3, 'Medium Severity Vulnerability Top 10 By Plugin Family', $center_border6_format );
++$SummaryReport_cnt;
$SummaryReport_worksheet->write($SummaryReport_cnt, 0, 'plugin Family',$center_border6_format);
$SummaryReport_worksheet->write($SummaryReport_cnt, 1, 'plugin id',$center_border6_format);
$SummaryReport_worksheet->write($SummaryReport_cnt, 2, 'plugin Name',$center_border6_format);
$SummaryReport_worksheet->write($SummaryReport_cnt, 3, 'count',$center_border6_format);
$SummaryReport_worksheet->set_column('A:M', 20);
++$SummaryReport_cnt;

my @medvuln_uniq_plugin_family = vuln_seperate_by_plugin(\@{$vulnerability_data{medvuln}});
foreach my $entry (@medvuln_uniq_plugin_family){
    my @tmp = @{$entry->{entries}};
    foreach my $t (@tmp){
        $SummaryReport_worksheet->write($SummaryReport_cnt, 0, $t->[5],$cell_format);
        $SummaryReport_worksheet->write($SummaryReport_cnt, 1, $t->[0],$cell_format);
        $SummaryReport_worksheet->write($SummaryReport_cnt, 2, $t->[3],$cell_format);
        $SummaryReport_worksheet->write($SummaryReport_cnt, 3, $t->[2],$cell_format);
        ++$SummaryReport_cnt;
    }
    # end of foreach my $t (@tmp)
}
# end of foreach my $entry (@medvuln_uniq_plugin_family)

my $isCompliancePresent = 0;
foreach my $k (keys %complaince){
    if ($complaince{"$k"}->[0] ne "") {
        $isCompliancePresent = 1;
        last;
    }
}
# end of foreach my $k (keys %complaince)

if ($isCompliancePresent == 1) {
    foreach my $k (keys %complaince){
        if ($complaince{"$k"}->[0] ne "") {
            $PolicySummaryReport_worksheet = $workbook->add_worksheet('PolicySummary Report Data');
            $PolicySummaryReport_worksheet->write_url( 'A1', $home_url, $url_format, $_);
            $PolicySummaryReport_worksheet->set_column('A:G', 20);
            $PolicySummaryReport_worksheet->autofilter('A3:F3');
            $PolicySummaryReport_worksheet->freeze_panes('G4');
            $PolicySummaryReport_cnt = 2;
            last;
        }
        # end of if ($complaince{"$k"}->[0] ne "") 
    }
    # end foreach my $k (keys %complaince)
    
    foreach my $k (keys %compliance_summary){
        if ($k !~ /SCAP/) {
            foreach my $k2 (keys %{$compliance_summary{$k}}){
                foreach my $k4 (keys %audit_result_type){
                    if (not $compliance_summary{$k}->{$k2}->{$k4}) {$compliance_summary{$k}->{$k2}->{$k4} = 0;}
                }
                # end of foreach my $k4 (keys %audit_result_type)
            }
            #end of foreach my $k2 (keys %{$compliance_summary{$k}})
        }
        # end of if ($k !~ /SCAP/)
    }
    # end of foreach my $k (keys %compliance_summary)
    
    $PolicySummaryReport_worksheet->write($PolicySummaryReport_cnt, 0, 'Complaince Family',$center_border6_format);
    $PolicySummaryReport_worksheet->write($PolicySummaryReport_cnt, 1, 'Compliance Check',$center_border6_format);
    my %result_type = %audit_result_type;
    
    my $PolicySummaryReport_row = 2;
    foreach my $k (keys %result_type){
        $PolicySummaryReport_worksheet->write($PolicySummaryReport_cnt, $PolicySummaryReport_row, $k,$center_border6_format);
        $result_type{$k} = $PolicySummaryReport_row;
        ++$PolicySummaryReport_row;
    }
    # end of foreach my $k (keys %result_type)
    ++$PolicySummaryReport_cnt;
    foreach my $k (keys %compliance_summary){
        foreach my $k2 (keys %{$compliance_summary{$k}}){
            $PolicySummaryReport_worksheet->write($PolicySummaryReport_cnt, 0, $k,$cell_format);
            $PolicySummaryReport_worksheet->write($PolicySummaryReport_cnt, 1, $k2,$cell_format);
            
            foreach my $k3 (keys %result_type){
                $PolicySummaryReport_worksheet->write($PolicySummaryReport_cnt, $result_type{$k3}, $compliance_summary{$k}->{$k2}->{$k3},$cell_format);
            }
            # end of foreach my $k4 (keys %audit_result_type)
            ++$PolicySummaryReport_cnt;
        }
        #end of foreach my $k2 (keys %{$compliance_summary{$k}})
    }
    # end of foreach my $k (keys %compliance_summary)
}
# end of if ($isCompliancePresent == 1)

print "Storing Plugin to IP Table\n";

if(keys %ip_vuln_data > 0){
    my $ip_vuln_data_ctr = 2;
    print "Storing Vulnerability to IP Summary Table\n";
    my $ip_vuln_data_worksheet = $workbook->add_worksheet('Vulnerability to IP Summary');
    $ip_vuln_data_worksheet->write_url( 'A1', $home_url, $url_format, $_);
    $ip_vuln_data_worksheet->keep_leading_zeros();
    $ip_vuln_data_worksheet->write(1, 0, 'File',$center_border6_format);
    $ip_vuln_data_worksheet->write(1, 1, 'Severity',$center_border6_format);
    $ip_vuln_data_worksheet->write(1, 2, 'Plugin ID',$center_border6_format);
    $ip_vuln_data_worksheet->write(1, 3, 'Plugin Name',$center_border6_format);
    $ip_vuln_data_worksheet->write(1, 4, 'IP Count',$center_border6_format);
    $ip_vuln_data_worksheet->write(1, 5, 'IP Addresses',$center_border6_format);
    $ip_vuln_data_worksheet->freeze_panes('C3');
    $ip_vuln_data_worksheet->autofilter('A2:F2');
    $ip_vuln_data_worksheet->set_column('A:C',20);
    $ip_vuln_data_worksheet->set_column('D:D',50);
    $ip_vuln_data_worksheet->set_column('E:E',10);
    $ip_vuln_data_worksheet->set_column('F:F',50);

    foreach my $file (keys %ip_vuln_data){
        foreach my $sev (keys %{$ip_vuln_data{$file}}){
            foreach my $plugin (keys %{$ip_vuln_data{$file}->{$sev}}){
                my $severity;
                if ($sev eq 4) {$severity = "Critical (4)"}
                elsif ($sev eq 3) {$severity = "High (3)"}
                elsif ($sev eq 2) {$severity = "Medium (2)"}
                elsif ($sev eq 1) {$severity = "Low (1)"}
                else {$severity = "Informational (0)"}
                
                my $ip = join ";", keys %{$ip_vuln_data{$file}->{$sev}->{$plugin}->{ip}};
                my $ip_cnt = keys %{$ip_vuln_data{$file}->{$sev}->{$plugin}->{ip}};
                $ip_vuln_data_worksheet->write($ip_vuln_data_ctr, 0, $file,$cell_format);
                $ip_vuln_data_worksheet->write($ip_vuln_data_ctr, 1, $severity,$cell_format);
                $ip_vuln_data_worksheet->write($ip_vuln_data_ctr, 2, $plugin,$cell_format);
                $ip_vuln_data_worksheet->write($ip_vuln_data_ctr, 3, $ip_vuln_data{$file}->{$sev}->{$plugin}->{pluginName},$cell_format);
                $ip_vuln_data_worksheet->write($ip_vuln_data_ctr, 4, $ip_cnt,$cell_format);
                $ip_vuln_data_worksheet->write($ip_vuln_data_ctr, 5, $ip,$cell_format);
                ++$ip_vuln_data_ctr;
            }
            # end of foreach my $plugin (keys %{$ip_vuln_data{$file}->{$sev}})
        }
        # end of foreach my $sev (keys %{$ip_vuln_data{$file}})
        print "";
    }
    # end of foreach my $file (keys %ip_vuln_data)
    
    print "";
}
# end of if(keys %ip_vuln_data > 0)

print "Storing Host Summary Report Table\n";
my $HostSummaryReport_worksheet = $workbook->add_worksheet('HostSummary Report Data');
$HostSummaryReport_worksheet->write_url( 'A1', $home_url, $url_format, $_);
$HostSummaryReport_worksheet->set_column('A:A', 60);
$HostSummaryReport_worksheet->set_column('B:B', 20);
my $HostSummaryReport_cnt = 1;

my @host_sum_array = ('operating-system','local-checks-proto','name','sev0','sev1','sev2','sev3','sev4','Minimum password len','Password history len','Maximum password age (d)',
                      'Password must meet complexity requirements','Minimum password age (d)','Forced logoff time (s)','Locked account time (s)','Time between failed logon (s)',
                      'Number of invalid logon before locked out (s)'
                      );
#

foreach my $entry (@host_sum_array){
    my %hash;
    %hash = host_summary_data (\@host_data,$entry);
    $HostSummaryReport_worksheet->merge_range( $HostSummaryReport_cnt,0, $HostSummaryReport_cnt, 1, "Host Summary Table $entry", $center_border6_format );
    ++$HostSummaryReport_cnt;
    if($entry =~ /sev/){$HostSummaryReport_worksheet->write($HostSummaryReport_cnt, 0, "The number of Hosts with $entry discovered",$center_border6_format)}
    else{$HostSummaryReport_worksheet->write($HostSummaryReport_cnt, 0, "$entry Values",$center_border6_format)}
    $HostSummaryReport_worksheet->write($HostSummaryReport_cnt, 1, 'Count',$center_border6_format);
    ++$HostSummaryReport_cnt;
    if ($hash{""} > 0){$hash{'Unknown'} = $hash{""};delete $hash{""};}
    my $row_start = $HostSummaryReport_cnt;
    my @temp;
    foreach my $entry (keys %hash){push @temp, [$entry , $hash{$entry}]}
    my $header = ['Values', 'Count'];
    my $pivot_data = \@temp;
    my $t = new Data::Table($pivot_data, $header, 0);
    if ($entry =~ /sev/){$t->sort("Values",0,1);}
    else{$t->sort("Count",0,1);}
    
    foreach my $entry (@{$t->{data}}){
        $HostSummaryReport_worksheet->write($HostSummaryReport_cnt, 0, $entry->[0],$cell_format);
        $HostSummaryReport_worksheet->write($HostSummaryReport_cnt, 1, $entry->[1],$cell_format);
        ++$HostSummaryReport_cnt;
    }
    my $row_end = $HostSummaryReport_cnt;
    my $chart = $workbook->add_chart( type => 'pie', embedded => 1  );
    my $chart_title = "Host Summary Table $entry";
    my $chart_sheet_name = 'HostSummary Report Data';
    $chart->add_series(
        name       => $chart_title,
        categories => [$chart_sheet_name, $row_start, $row_end-1, 0, 0],
        values     => [$chart_sheet_name, $row_start, $row_end-1, 1, 1]
    );
    # Add a title.
    $chart->set_title( name => $chart_title);
    # Set an Excel chart style. Colors with white outline and shadow.
    $chart->set_style( 10 );
    # Insert the chart into the worksheet (with an offset).
    $HostSummaryReport_worksheet->insert_chart( $row_start, 3, $chart, 1, 40 );    
    $HostSummaryReport_cnt = $HostSummaryReport_cnt+10;
}
# end of foreach my $entry (@host_sum_array)

$Home_worksheet->set_first_sheet();
$Home_worksheet->activate();
my @worksheet_names;
for my $sheet($workbook->sheets()){push @worksheet_names, $sheet->get_name();}
$Home_worksheet->merge_range( 'A1:B1', "Home Page for Nessus Report_$report_file", $center_border6_format );
my $Home_cnt = 1;
$Home_worksheet->set_column('A:A', 70);
$Home_worksheet->write($Home_cnt, 0, "Worksheets");

foreach (@worksheet_names){
    if ($_ ne "Home Worksheet"){
        my $url = "internal\:\'$_\'\!A1";
        $Home_worksheet->write_url( $Home_cnt, 0, $url, $url_format, $_);
        ++$Home_cnt;
    }
}
# end of foreach (@worksheet_names)

my @target_list;
foreach my $t1 (@targets){
    my @tmp = split /\,/, $t1->{value};
    foreach my $t2 (@tmp){
        if($t2 =~ /\/32/){$target_cnt = $target_cnt + 1;}
        elsif($t2 =~ /\/31/){$target_cnt = $target_cnt + 2;}
        elsif($t2 =~ /\/30/){$target_cnt = $target_cnt + 4;}
        elsif($t2 =~ /\/29/){$target_cnt = $target_cnt + 8;}
        elsif($t2 =~ /\/28/){$target_cnt = $target_cnt + 16;}
        elsif($t2 =~ /\/27/){$target_cnt = $target_cnt + 32;}
        elsif($t2 =~ /\/26/){$target_cnt = $target_cnt + 64;}
        elsif($t2 =~ /\/25/){$target_cnt = $target_cnt + 128;}
        elsif($t2 =~ /\/24/){$target_cnt = $target_cnt + 256;}
        elsif($t2 =~ /\/23/){$target_cnt = $target_cnt + 512;}
        elsif($t2 =~ /\/22/){$target_cnt = $target_cnt + 1024;}
        elsif($t2 =~ /\/21/){$target_cnt = $target_cnt + 2048;}
        elsif($t2 =~ /\/20/){$target_cnt = $target_cnt + 4096;}
        elsif($t2 =~ /\/19/){$target_cnt = $target_cnt + 8192;}
        elsif($t2 =~ /\/18/){$target_cnt = $target_cnt + 16384;}
        elsif($t2 =~ /\/17/){$target_cnt = $target_cnt + 32768;}
        elsif($t2 =~ /\/16/){$target_cnt = $target_cnt + 65536;}
        elsif($t2 =~ /\/15/){$target_cnt = $target_cnt + 131072;}
        elsif($t2 =~ /\/14/){$target_cnt = $target_cnt + 262144;}
        elsif($t2 =~ /\/13/){$target_cnt = $target_cnt + 524288;}
        elsif($t2 =~ /\/12/){$target_cnt = $target_cnt + 1048576;}
        elsif($t2 =~ /\/11/){$target_cnt = $target_cnt + 2097152;}
        elsif($t2 =~ /\/10/){$target_cnt = $target_cnt + 4194304;}
        elsif($t2 =~ /\/9/){$target_cnt = $target_cnt + 8388608;}
        elsif($t2 =~ /\/8/){$target_cnt = $target_cnt + 16777216;}
        elsif($t2 =~ /\/7/){$target_cnt = $target_cnt + 33554432;}
        elsif($t2 =~ /\/6/){$target_cnt = $target_cnt + 67108864;}
        elsif($t2 =~ /\/5/){$target_cnt = $target_cnt + 134217728;}
        elsif($t2 =~ /\/4/){$target_cnt = $target_cnt + 268435456;}
        elsif($t2 =~ /\/3/){$target_cnt = $target_cnt + 536870912;}
        elsif($t2 =~ /\/2/){$target_cnt = $target_cnt + 1073741824;}
        elsif($t2 =~ /\/1/){$target_cnt = $target_cnt + 2147483648;}
        elsif($t2 =~ /\/0/){$target_cnt = $target_cnt + 4294967296;}
        elsif($t2 =~ /($ip_add_regex)(-)($ip_add_regex)/){
            my @tmp_nets = split /\-/,$t2;
            my @net1 = split /\./,$tmp_nets[0];
            my @net2 = split /\./,$tmp_nets[1];
            my $net1_ip_number = 0;
            foreach my $octet (@net1) {$net1_ip_number <<= 8;$net1_ip_number |= $octet;}
            my $net2_ip_number = 0;
            foreach my $octet (@net2) {$net2_ip_number <<= 8;$net2_ip_number |= $octet;}
            my $net_cnt_tmp = $net2_ip_number - $net1_ip_number + 1;
            $target_cnt = $target_cnt + $net_cnt_tmp;
        }
        else{++$target_cnt;}
        push @target_list, $t2;
    }
    # end of foreach my $t2 (@tmp)
}
# end of foreach my $t1 (@targets)

my $most_high_common_vuln = "";
if($vulnerability_data{highvuln}->[0] ne ""){
    my $header = ["plugin id0","Severity1","count2","plugin Name3","File4","plugin Family5","Bid6","CVE7","OSVDB8","Solution9","Description10"];
    my $pivot_data = \@{$vulnerability_data{highvuln}};
    foreach my $p (@{$pivot_data}){
        my @tmp = split /\,/,$p;
        $p = ["$tmp[0]","$tmp[1]","$tmp[2]","$tmp[3]","$tmp[4]","$tmp[5]","$tmp[6]","$tmp[7]","$tmp[8]","$tmp[9]","$tmp[10]"];
    }
    my $t = new Data::Table($pivot_data, $header, 0);
    $t->sort("count2",0,1,"CVE7",1,0,"OSVDB8",1,0);
    my @t = @{$t->{data}};
    
    my %sorted_keys = %{$vuln_totals{3}};
    my @sorted_keys2 = sort { $sorted_keys{$a} <=> $sorted_keys{$b} } keys %sorted_keys;
    $most_high_common_vuln = pop @sorted_keys2;
    foreach my $m (@{$vulnerability_data{highvuln}}){
        if($most_high_common_vuln eq $m->[0]){$most_high_common_vuln = $m;last;}
    }
    # end of foreach my $m (@{$vulnerability_data{highvuln}})
    
    
    print "";
}
# end of if($highvuln[0] ne "")

my $most_critical_common_vuln = "";
if($vulnerability_data{criticalvuln}->[0] ne ""){
    my $header = ["plugin id0","Severity1","count2","plugin Name3","File4","plugin Family5","Bid6","CVE7","OSVDB8","Solution9","Description10"];
    my $pivot_data = \@{$vulnerability_data{criticalvuln}};
    foreach my $p (@{$pivot_data}){
        my @tmp = split /\,/,$p;
        $p = ["$tmp[0]","$tmp[1]","$tmp[2]","$tmp[3]","$tmp[4]","$tmp[5]","$tmp[6]","$tmp[7]","$tmp[8]","$tmp[9]","$tmp[10]"];
    }
    my $t = new Data::Table($pivot_data, $header, 0);
    $t->sort("count2",0,1,"CVE7",1,0,"OSVDB8",1,0);
    my @t = @{$t->{data}};
    
    my %sorted_keys = %{$vuln_totals{4}};
    my @sorted_keys2 = sort { $sorted_keys{$a} <=> $sorted_keys{$b} } keys %sorted_keys;
    $most_critical_common_vuln = pop @sorted_keys2;
    foreach my $m (@{$vulnerability_data{criticalvuln}}){
        if($most_critical_common_vuln eq $m->[0]){$most_critical_common_vuln = $m;last;}
    }
    # end of foreach my $m (@{$vulnerability_data{criticalvuln}})
}
# end of if($criticalvuln[0] ne "")

my $total_discovered = keys (%total_discovered);
my $total_critical = @{$vulnerability_data{criticalvuln}};
my $total_critical2 = keys %{$vuln_totals{4}};

my $total_high = @{$vulnerability_data{highvuln}};
my $total_high2 = keys %{$vuln_totals{3}};

my $total_med = @{$vulnerability_data{medvuln}};
my $total_med2 = keys %{$vuln_totals{2}};

my $total_low = @{$vulnerability_data{lowvuln}};
my $total_low2 = keys %{$vuln_totals{1}};

my $total_none = @{$vulnerability_data{nonevuln}};
my $total_none2 = keys %{$vuln_totals{0}};

my $total_discovered_row = $total_discovered +2;

++$Home_cnt;++$Home_cnt;
$Home_worksheet->merge_range( $Home_cnt, 0, $Home_cnt, 1, "Overall Summary Data", $center_border6_format );
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Number of IP's Scanned");
$Home_worksheet->write($Home_cnt, 1, $target_cnt);
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Number of Discovered Systems");
$Home_worksheet->write($Home_cnt, 1, "$total_discovered");
++$Home_cnt;
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Total Unique Critical Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, $total_critical2);
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Total Unique High Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, $total_high2);
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Total Unique Medium Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, $total_med2);
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Total Unique Low Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, $total_low2);
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Total Unique Informational Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, $total_none2);
++$Home_cnt;
++$Home_cnt;
$total_critical = $total_critical+2;
$Home_worksheet->write($Home_cnt, 0, "Total Count of Critical Severity Vulnerability");
if ($total_critical == 2) {$Home_worksheet->write($Home_cnt, 1, "N/A")}
else{$Home_worksheet->write($Home_cnt, 1, "\=SUM\(critical\!E3\:E$total_critical\)")}
++$Home_cnt;
$total_high = $total_high+2;
$Home_worksheet->write($Home_cnt, 0, "Total Count of High Severity Vulnerability");
if ($total_high == 2) {$Home_worksheet->write($Home_cnt, 1, "N/A")}
else{$Home_worksheet->write($Home_cnt, 1, "\=SUM\(high\!E3\:E$total_high\)");}
++$Home_cnt;
$total_med =$total_med+2;
$Home_worksheet->write($Home_cnt, 0, "Total Count of Medium Severity Vulnerability");
if ($total_med == 2) {$Home_worksheet->write($Home_cnt, 1, "N/A")}
else{$Home_worksheet->write($Home_cnt, 1, "\=SUM\(medium\!E3\:E$total_med\)");}
++$Home_cnt;
$total_low = $total_low+2;
$Home_worksheet->write($Home_cnt, 0, "Total Count of Low Severity Vulnerability");
if ($total_low == 2) {$Home_worksheet->write($Home_cnt, 1, "N/A")}
else{$Home_worksheet->write($Home_cnt, 1, "\=SUM\(low\!E3\:E$total_low\)");}
++$Home_cnt;
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "The most common Critical Severity vulnerability");
if($most_critical_common_vuln){$Home_worksheet->write($Home_cnt, 1, $most_critical_common_vuln->[3]);}
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "The most common high Severity vulnerability");

####### PUT IN TESTING IS $most_high_common_vuln is a string or hash

if($most_high_common_vuln){$Home_worksheet->write($Home_cnt, 1, $most_high_common_vuln->[3]);}
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Number of System with a critical(4) Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, "\=COUNTIF\(HostConfigData\!M3\:M$total_discovered_row\,\"\>0\"\)");
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Number of System with a High(3) Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, "\=COUNTIF\(HostConfigData\!L3\:L$total_discovered_row\,\"\>0\"\)");
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Number of System with a Medium(2) Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, "\=COUNTIF\(HostConfigData\!K3\:K$total_discovered_row\,\"\>0\"\)");
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Number of System with a Low(1) Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, "\=COUNTIF\(HostConfigData\!J3\:J$total_discovered_row\,\"\>0\"\)");
++$Home_cnt;
$Home_worksheet->write($Home_cnt, 0, "Number of System with a Informational(NONE-0) Severity Vulnerability");
$Home_worksheet->write($Home_cnt, 1, "\=COUNTIF\(HostConfigData\!I3\:I$total_discovered_row\,\"\>0\"\)");
++$Home_cnt;
++$Home_cnt;

$workbook->close();
print $new_stuff;
print "\n\ncompleted\n\nThe Data is stored in $dir/$report_prefix\_$report_file.xlsx";
print "\nEND OF VERSION 0.24\n";

__END__

##################################################################################### BEGIN SAMPLE NEW WORKSHEET
my $SampleData_ctr = 2;
print "Storing SampleData Table\n";
my $SampleData_worksheet = $workbook->add_worksheet('SampleData');
$SampleData_worksheet->write_url( 'A1', $home_url, $url_format, $_);
$SampleData_worksheet->keep_leading_zeros();
$SampleData_worksheet->write(1,  0, 'File',$center_border6_format);
$SampleData_worksheet->write(1,  1, 'IP Address',$center_border6_format);
$SampleData_worksheet->write(1,  2, 'FQDN',$center_border6_format);
$SampleData_worksheet->write(1,  3, 'Netbios Name',$center_border6_format);
$SampleData_worksheet->write(1,  4, "ROW4",$center_border6_format);
$SampleData_worksheet->write(1,  5, "ROW5",$center_border6_format);
$SampleData_worksheet->write(1,  6, "ROW6",$center_border6_format);
$SampleData_worksheet->write(1,  7, "ROW7",$center_border6_format);
$SampleData_worksheet->write(1,  8, "ROW8",$center_border6_format);
$SampleData_worksheet->write(1,  9, "ROW9",$center_border6_format);
$SampleData_worksheet->write(1, 10, "ROW10",$center_border6_format);
$SampleData_worksheet->write(1, 11, "ROW11",$center_border6_format);
$SampleData_worksheet->write(1, 12, "ROW12",$center_border6_format);
$SampleData_worksheet->write(1, 13, "ROW13",$center_border6_format);
$SampleData_worksheet->write(1, 14, "ROW14",$center_border6_format);
$SampleData_worksheet->write(1, 15, "ROW15",$center_border6_format);
$SampleData_worksheet->write(1, 16, "ROW16",$center_border6_format);
$SampleData_worksheet->write(1, 17, "ROW17",$center_border6_format);
$SampleData_worksheet->write(1, 18, "ROW18",$center_border6_format);
$SampleData_worksheet->write(1, 19, "ROW19",$center_border6_format);
$SampleData_worksheet->write(1, 20, "ROW20",$center_border6_format);
$SampleData_worksheet->write(1, 21, "ROW21",$center_border6_format);
$SampleData_worksheet->freeze_panes('C3');
$SampleData_worksheet->autofilter('A2:Z2');
$SampleData_worksheet->set_column('A:Z',20);
$SampleData_worksheet->set_column('B:B',15);
$SampleData_worksheet->set_column('C:C',25);
$SampleData_worksheet->set_column('D:D',15);
$SampleData_worksheet->set_column('E:H',15);

foreach my $host (@host_data){
    $SampleData_worksheet->write($SampleData_ctr, 0,  $host->{"file"},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 1,  $host->{"host-ip"},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 2,  $host->{"host-fqdn"},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 3,  $host->{"netbios-name"},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 4,  $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 5,  $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 6,  $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 7,  $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 8,  $host->{vuln_cnt}->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 9,  $host->{vuln_cnt}->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 10, $host->{vuln_cnt}->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 11, $host->{vuln_cnt}->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 12, $host->{vuln_cnt}->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 13, $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 14, $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 15, $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 16, $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 17, $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 18, $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 19, $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 20, $host->{VAR1},$cell_format);
    $SampleData_worksheet->write($SampleData_ctr, 21, $host->{VAR1},$cell_format);
    ++$SampleData_ctr;
}
# end foreach (@SampleData)

##################################################################################### END SAMPLE NEW WORKSHEET
