#!/usr/bin/python

##############################################################
# Original Credits:
# gnxmerge.py - Glens Nmap XML merger
# Merge multiple nmap XML files

# Project URL: https://bitbucket.org/memoryresident/gnxtools
# Author URL: https://www.glenscott.net
##############################################################

import sys, argparse, copy, os, time

try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


def handle_opts():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Nmap XML Merger - Merges <host> sections from multiple Nmap XML files',
        usage='%(prog)s -sources=./file.xml,file2.xml,/path/to/files'
    )
    parser.add_argument('-s', '-sources', action='store', dest='sources',
                        required=True,
                        help='Comma separated list of paths to files and/or folder contents to merge. An .xml extension is not mandatory; all files and contents of target folder will be (non-recursively) processed, regardless of extension. If files are present which are not valid XML, they will be skipped with warnings.')

    args = parser.parse_args()
    # return sources_list for now, modify if other arguments come along
    return (args.sources).split(",")


def start_xml(script_start_time):
    # Concatenate the script arguments to a string
    scriptargs = ""
    for argnum in range(0, len(sys.argv)):
        scriptargs = scriptargs + " " + str(sys.argv[argnum])

    # Set some vars used to mimic the official nmap file format
    nmaprun_attribs = {'scanner': sys.argv[0], 'args': scriptargs,
                       'start': str(script_start_time), 'version': '1.0',
                       'xmloutputversion': '1.04'}

    nmaprun = ET.Element('nmaprun', nmaprun_attribs)

    # Append a comment prior to starting root xml
    comment = ET.Comment('Merged nmap XML files')
    nmaprun.append(comment)

    nmaprun_verbose_attribs = {'level': '0'}
    nmaprun_debug_attribs = {'level': '0'}
    nmaprun_verbose = ET.SubElement(nmaprun, 'verbose', nmaprun_verbose_attribs)
    nmaprun_debug = ET.SubElement(nmaprun, 'debug', nmaprun_debug_attribs)

    return nmaprun


def finalise_xml(nmaprun_merged_results, script_start_time):
    nmaprun = nmaprun_merged_results[0]
    total_hosts = nmaprun_merged_results[1]
    total_seconds = nmaprun_merged_results[2]
    total_files = nmaprun_merged_results[3]
    nmaprun_string = ET.tostring(nmaprun)
    total_script_time = int(time.time()) - script_start_time;

    summary_string = (
        'Nmap XML merge done at ' + time.strftime("%c") + "; " + str(
            total_hosts) + ' total hosts found in ' + str(
            total_files) + ' files; Merge completed in ' + str(
            total_script_time) + ' seconds')

    finished_attribs = {}
    finished_attribs["time"] = str(int(time.time()))
    finished_attribs["timestr"] = time.strftime("%c")
    finished_attribs["elapsed"] = str(total_seconds)
    finished_attribs["summary"] = summary_string
    finished_attribs["exit"] = 'success'

    hosts_attribs = {}
    hosts_attribs["up"] = str(total_hosts)
    hosts_attribs["down"] = '0'
    hosts_attribs["total"] = str(total_hosts)

    runstats = ET.SubElement(nmaprun, 'runstats')
    finished = ET.SubElement(runstats, 'finished', finished_attribs)
    hosts = ET.SubElement(runstats, 'hosts', hosts_attribs)

    return nmaprun


def merge_hosts(nmaprun, file_list):
    # iterate through each file in the target folder or each file passed as an option.
    # for each file, the entire <host> section is copied and appended to
    # the XML object being built.

    # init these to zero before we start counting
    total_hosts = 0
    total_seconds = 0
    bad_file_list = []

    for current_file in file_list:
        try:
            current_nmap_file_blob = ET.ElementTree(file=current_file);

            for current_host in current_nmap_file_blob.findall('host'):
                # build our stats here
                total_hosts = total_hosts + 1
                total_seconds = (
                    total_seconds + calc_seconds(
                        current_host.attrib['starttime'],
                        current_host.attrib['endtime']))
                nmaprun.append(copy.deepcopy(current_host))

        except:
            bad_file_list.append(current_file)

    # work out how many files were successfully processed
    files_processed = len(file_list) - len(bad_file_list)

    nmaprun_merge_results = [nmaprun, total_hosts, total_seconds,
                             len(file_list)]
    return nmaprun_merge_results, bad_file_list, files_processed, total_hosts


def calc_seconds(starttime, finishtime):
    # calculate seconds duration of this host
    totaltime = int(finishtime) - int(starttime)
    return totaltime


def input_file_list(sources_list):
    # get the args, add all files to list
    file_list = []
    for target in sources_list:
        if os.path.isdir(target) == True:
            dirlist = os.listdir(target)
            for file in dirlist:
                file_list.append(target + file)
        else:
            file_list.append(target)
    return file_list


def output_results(nmap_file_preamble, nmaprun, merge_job_output):
    bad_file_list = merge_job_output[1]
    files_processed = merge_job_output[2]
    total_hosts = merge_job_output[3]

    print nmap_file_preamble
    nmaprun_string = ET.tostring(nmaprun)
    print nmaprun_string
    for badfile in bad_file_list:
        # Throw a warning to stderror but dont interfere with the working output
        # there might be a bunch of files we dont care about in the same folder, such as nmap 'normal' outputs.
        sys.stderr.write("\n WARNING:" + badfile + " skipped (not xml?)")
    # print general end status
    sys.stderr.write("\n\nMerged " + str(total_hosts) + " hosts from " + str(
        files_processed) + " xml files. " + str(
        len(bad_file_list)) + " invalid files skipped.")


def main():
    # Running time.time() through int as the former returns epoch in the form of a float which is not the official format.
    # discovered this because ndiff was breaking on the merged output. Also applied to time.time call in finalise_xml
    script_start_time = int(time.time())
    merge_job_output = []

    nmap_file_preamble = ('<?xml version="1.0"?> \n'
                          '<!DOCTYPE nmaprun PUBLIC "-//IDN nmap.org//DTD Nmap XML 1.04//EN" "https://svn.nmap.org/nmap/docs/nmap.dtd"> \n'
                          '<?xml-stylesheet href="https://svn.nmap.org/nmap/docs/nmap.xsl" type="text/xsl"?> \n\n'
                          )

    file_list = input_file_list(handle_opts())
    nmaprun_skel = start_xml(script_start_time)
    merge_job_output = merge_hosts(nmaprun_skel, file_list)

    nmaprun_merged_results = merge_job_output[0]
    nmaprun_finalised = finalise_xml(nmaprun_merged_results, script_start_time)
    output_results(nmap_file_preamble, nmaprun_finalised, merge_job_output)


if __name__ == "__main__":
    main()
