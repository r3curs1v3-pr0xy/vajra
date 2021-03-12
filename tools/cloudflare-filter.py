import socket
import requests
from ipaddress import ip_network, ip_address
import argparse
import os

parser = argparse.ArgumentParser(description='Filter Cloudflare Ip')
parser.add_argument(
    '-d', '--domain', help='Domain name of the taget [ex : hackerone.com]')
parser.add_argument(
    '-f', '--file', help='Domain name of the taget [ex : hackerone.com]')
args = parser.parse_args()


def host(url):
    ipaddr = socket.gethostbyname(url)
    return(ipaddr)

# Cloudflare IP Filter


def output_valid_ips(ips):
    ipvs4 = "https://www.cloudflare.com/ips-v4"
    ipvs6 = "https://www.cloudflare.com/ips-v6"

    ipranges = requests.get(ipvs4).text.split(
        "\n")[:-1]  # removing last trailing space
    ipranges += requests.get(ipvs6).text.split("\n")[
        :-1
    ]  # removing last trailing space
    nets = []
    for iprange in ipranges:
        nets.append(ip_network(iprange))
    valid = True
    for net in nets:
        if ip_address(ips) in net:
            valid = False
            break
    if valid:
        if args.domain:
            with open(args.domain+"_ip.txt", 'a') as fp:
                fp.write(ips)
                fp.close()
        if args.file:
            with open(args.file+"_ip.txt", 'a') as fp:
                fp.write(ips+'\n')
                fp.close()


if args.domain:
    output_valid_ips(host(args.domain))

if args.file:
    a = []
    with open(args.file, 'r') as fpss:
        data = fpss.readlines()
        try:
            for line in data:
                a.append(host(line.strip()))
        except Exception as e:
            pass
    fpss.close()
    for x in a:
        output_valid_ips(x.strip())

