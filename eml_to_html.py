#!/usr/bin/python

'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Parses an .eml file into separate files suitable for use with phishing frenzy
'''

import sys
import argparse
import email
import os
from BeautifulSoup import BeautifulSoup
import urllib

def main(argv):
    
    parser = argparse.ArgumentParser(description='Convert an .eml file into an html file suitable for use with phishing frenzy.')
    parser.add_argument("infile", action="store", help="Input file")
    
    args = parser.parse_args()  
    
    inputfile = open(args.infile, "rb")
    
    #See if this will be used for phishing frenzy or as a standalone attack
    #Yes option will use phishing-frenzy tags and check for additional options
    global phishing_frenzy
    phishing_frenzy = False
    global replace_links
    replace_links = False
    global imbed_tracker
    imbed_tracker = False
    
    phishing_frenzy = raw_input("\nShould links and images be formatted for use in phishing frenzy? [yes]")
    if not ("n" in phishing_frenzy or "N" in phishing_frenzy):
        phishing_frenzy = True
        replace_links = raw_input("\nWould you like to replace all links with phishing-frenzy tags? [yes]")
        if not ("n" in replace_links or "N" in replace_links):
            replace_links = True
        imbed_tracker = raw_input("\nWould you like to imbed the phishing-frenzy tracking image tag? [yes]")
        if not ("n" in imbed_tracker or "N" in imbed_tracker):
            imbed_tracker = True
    
    #change working directory so we are in same directory as input file!
    os.chdir(os.path.dirname(inputfile.name))
    
    message = email.message_from_file(inputfile) 
    
    extract_payloads(message)

        
def extract_payloads(msg):
        if msg.is_multipart():
            #message / section is multi-part; loop part back through the extraction module
            print "Multi-part section encountered; extracting individual parts from section..."
            for part in msg.get_payload():
                extract_payloads(part)
        else:
            sectionText=msg.get_payload(decode=True)
            contentType=msg.get_content_type()
            filename=msg.get_filename()                 #this is the filename of an attachment
            
            soup = BeautifulSoup(sectionText)                

            if contentType=="text/html":
                print "Processing HTML section..."
                
                ########################################
                #replace links with phishing frenzy tags
                ########################################
                if replace_links==True:                    
                    for a in soup.findAll('a'):
                        a['href'] = '<%= @url %>'
                
                ###############################################
                #Detect hyperlinked images and download locally
                ###############################################
                imageList = []
                
                for tag in soup.findAll('img', src=True):
                    imageList.append(tag['src'])
            
                if not imageList:
                    pass
                else:
                    print "The following linked images were detected in the HTML:"
                    for url in imageList:
                        print url
                        
                    download_images = raw_input("\nWould you like to download these and store locally? [yes]")
                    
                    if not ("n" in download_images or "N" in download_images):
                        print "Downloading images..."
                        for url in imageList:
                            filename = url.split('/')[-1].split('#')[0].split('?')[0]
                            open(filename,"wb").write(urllib.urlopen(url).read())
                            
                            #Does not appear that using PF attachment tag is necessary; just use filename?!?
                            if phishing_frenzy==True:
                                pass
                                #filename = "<%= image_tag attachments['"+filename+"'].url %>"
                            soup = BeautifulSoup(str(soup).decode("UTF-8").replace(url,filename).encode("UTF-8"))
                
                if imbed_tracker == True:
                    soup.body.insert(len(soup.body.contents), '<img src="<%= @image_url %>" alt="" />')
                
                ##########################################
                #Clean up html output and make it readable
                ##########################################                               
                sectionText = soup.prettify()
                sectionText = sectionText.replace('&lt;','<')
                sectionText = sectionText.replace('&gt;','>')
                
                print sectionText
                
                if phishing_frenzy==True:
                    export_part(sectionText,"email.html.erb")
                else:
                    export_part(sectionText,"email.html")
                
            elif contentType=="text/plain":
                ##TODO: Need to fix link cleanup of text section; beautiful soup doesn't replace hyperlinks in text file!
                print "Processing text section..."
                
                if phishing_frenzy==True:
                    export_part(sectionText,"email.txt.erb")
                else:
                    export_part(sectionText,"email.txt")
                
            elif filename:
                print "Processing attachment "+filename+"..."
                export_part(sectionText,filename)
            else:
                print "section is of unknown type ("+str(contentType)+")...skipping..."  
        
        
def export_part(sectionText,filename):
    open(filename,"wb").write(sectionText)

    
if __name__ == "__main__":
    main(sys.argv[1:])
