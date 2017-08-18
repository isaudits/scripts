#!/usr/bin/python
'''
@author: Matthew C. Jones, CPA, CISA, OSCP
IS Audits & Consulting, LLC
TJS Deemer Dana LLP

Email crawler / scraping script

See README.md for licensing information and credits

'''

import argparse
from urlparse import urlparse

try:
    from scrapy.selector import Selector
    from scrapy.linkextractors import LinkExtractor
    from scrapy.spiders import Rule, CrawlSpider
    from scrapy.crawler import CrawlerProcess
except:
    print "Scrapy dependency not met"
    exit()

harvested_emails=[]

class EmailSpider(CrawlSpider):
    #NOTE - we are passing start_urls and allowed_domains at time crawler process is called in main()
    
    name = "email_spider"
    start_urls = ["www.example.com"]            # overwritten when called
    allowed_domains = ["example.com"]           # overwritten when called
    
    # This spider has one rule: extract all (unique and canonicalized) links, follow them and parse them using the parse_items method
    rules = [
        Rule(
            LinkExtractor(
                canonicalize=True,
                unique=True
            ),
            follow=True,
            callback="parse_items"
        )
    ]
    
    # Method for parsing results; in this case, extract email addresses
    def parse_items(self, response):

        sel = Selector(response)

        emails = sel.xpath('//body').re('([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)')

        for item in zip(emails):
            email = str(item[0])
            if not email in harvested_emails:
                print "found " + email + " at " + response.url
                harvested_emails.append(email)
    
def main():
   
    #------------------------------------------------------------------------------
    # Configure argparse to handle command line arguments
    #------------------------------------------------------------------------------
    desc = "Email harvesting script"
    
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument('site_url', action='store', nargs='?',
                        help='Website to crawl'
    )
    args = parser.parse_args()
    
    site_url = args.site_url
    
    #------------------------------------------------------------------------------
    # Main script - here we go
    #------------------------------------------------------------------------------
    
    # Looks like a domain name was passed instead of URL; prepend http://
    if not site_url[0:4] == "http":
        site_url = "http://" + site_url
    
    parsed_url = urlparse(site_url)
    site_domain = parsed_url.netloc
        
    crawler_process = CrawlerProcess({
        'USER_AGENT': 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)',
        'LOG_LEVEL': 'WARNING',
        'DOWNLOAD_HANDLERS': {'s3': None,}      #this is to fix error with version of scrapy in Kali repo - https://stackoverflow.com/questions/31048130/scrapy-gives-urlerror-urlopen-error-timed-out
        })
    
    print "Harvesting emails from " + site_url + "..."
    crawler_process.crawl(EmailSpider, start_urls=[site_url], allowed_domains=[site_domain])
    crawler_process.start()
    
    if harvested_emails:
        print "\nFound " + str(len(harvested_emails)) + " email addresses on " + site_url + ":"
        for email in harvested_emails:
            print email
    else:
        print "\nNo email addresses found. Sorry!"
    
if __name__ == '__main__':
    main()