import dns.resolver
import sys
import argparse


def cname(urls, domain):
    for url in urls:
        try:
            if 'http://' or 'https://' in url:
                url = url.replace('https://', '')
                url = url.replace('http://', '')
            resolve = dns.resolver.query(url.strip(), 'CNAME')
            for rdata in resolve:
                cdata = rdata.to_text()
                if domain not in cdata:
                    print("Target is Vulnerable: "+cdata+" with subdomain "+url)
        except:
            print("")


parser = argparse.ArgumentParser(description='A python tool to check for subdomain takeover.')
parser.add_argument('-d', '--domain', help='Domain name of the taget [ex : hackerone.com]')
parser.add_argument('-f', '--file', help='Provide location of subdomain file to check for takeover if subfinder is not installed. [ex: --file /path/of/subdomain/file]')
parser.add_argument('-o', '--output', help='Output unique subdomains of sublist3r and subfinder to text file [ex: --output uniqueURL.txt]', default='uniqueURL.txt')
args = parser.parse_args()

subdomains = open(args.file, "r").readlines()
cname(subdomains, args.domain)
