import socket
import requests
from ipaddress import ip_network, ip_address
import argparse
import os

parser = argparse.ArgumentParser(description='Filter Cloudflare IP')
parser.add_argument(
    '-d', '--domain', help='Domain name of the taget [ex : hackerone.com]')
parser.add_argument(
    '-f', '--file', help='Domain name of the taget [ex : hackerone.com]')
args = parser.parse_args()


def host(url):
    return socket.gethostbyname(url)


def cloudflare_ips():
    ipvs4 = 'https://www.cloudflare.com/ips-v4'
    ipvs6 = 'https://www.cloudflare.com/ips-v6'

    ipranges = requests.get(ipvs4).text.split("\n")[:-1]    # removing last trailing space
    ipranges += requests.get(ipvs6).text.split("\n")[:-1]   # removing last trailing space

    return ipranges


# Cloudflare IP Filter
def output_valid_ips(ips):
    nets = []

    ipranges = cloudflare_ips()

    print(ipranges)

    for iprange in ipranges:
        nets.append(ip_network(iprange))

    validIPs = []

    for ip in ips:
        for net in nets:
            if ip_address(ip) not in net:
                validIPs.append(ip)

                if args.domain:
                    break

    if args.domain and len(validIPs) == 1:
        file_name = args.domain + '_ip.txt'
        with open(file_name, 'a') as fp:
            if os.path.getsize(file_name) == 0:
                fp.write(ips[0])
            else:
                fp.write('\n' + ips[0])

    if args.file and len(validIPs) >= 1:
        with open(args.file + '_ip.txt', 'a') as fp:
            fp.write('\n'.join(ips) + '\n')


if args.domain:
    output_valid_ips([host(args.domain)])

if args.file:
    ips = []

    with open(args.file, 'r') as fp:
        try:
            data = fp.readlines()

            for line in data:
                ips.append(host(line.strip()))
        except Exception as e:
            raise e

    output_valid_ips(ips)
