#!/usr/bin/python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Merge multiple CSV files into a single output file with only one header row
NOTE - ALL FILES MUST HAVE SAME HEADER / FORMAT TO WORK PROPERLY

See README.md for licensing information and credits

'''

import argparse
import os
import glob

def main():
   
    #------------------------------------------------------------------------------
    # Configure Argparse to handle command line arguments
    #------------------------------------------------------------------------------
    desc = "Merge multiple CSV files into a single output file"
    
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('input_folder', action='store', nargs='?',
                        help='Directory containing CSV files to merge \n \
                                (defaults to working directory if none specified)'
    )
    args = parser.parse_args()
    
    input_folder = args.input_folder

    
    #------------------------------------------------------------------------------
    # Main stuff
    #------------------------------------------------------------------------------

    if not input_folder:
        input_folder = os.getcwd()
        print 'no directory specified - using working directory:'
        print input_folder
        print ''
        
    merge_csv(input_folder)


def merge_csv(input_folder):
    
    csv_files = glob.glob(os.path.join(input_folder,"*.csv"))
    output_file = os.path.join(input_folder, "merged.csv")
    
    header_saved = False
    with open(output_file,'wb') as fout:
        for filename in csv_files:
            with open(filename) as fin:
                header = next(fin)
                if not header_saved:
                    fout.write(header)
                    header_saved = True
                for line in fin:
                    fout.write(line)
                    
if __name__ == '__main__':
    main()