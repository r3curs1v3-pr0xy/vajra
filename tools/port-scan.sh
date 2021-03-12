#!/bin/bash

cd ./tools/ && python3 cloudflare-filter.py -d $1

file=$1_ip.txt
if [ -f "$file" ]; then
    if [ "$2" = "small" ]; then
        masscan -iL $1_ip.txt -p 0-10000 --rate 1000 -oL $1_result.txt 
        cat $1_result.txt | cut -c 10-18 |cut -d " " -f1 > $1_open-ports.txt
        rm -f $1_ip.txt $1_result.txt
    fi
 
    if [ "$2" = "medium" ]; then
        masscan -iL $1_ip.txt -p 0-30000 --rate 1500 -oL $1_result.txt 
        cat $1_result.txt | cut -c 10-18 |cut -d " " -f1 > $1_open-ports.txt
        rm -f $1_ip.txt $1_result.txt
    fi 
   
    if [ "$2" = "full" ]; then
        masscan -iL $2_ip.txt -p 0-65534 --rate 1500 -oL $1_result.txt 
        cat $1_result.txt | cut -c 10-18 |cut -d " " -f1 > $1_open-ports.txt
        rm -f $1_ip.txt $1_result.txt
    fi

else
    echo "Target is Cloudflare Protected" > $1_open-ports.txt
fi