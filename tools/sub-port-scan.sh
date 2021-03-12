#!/bin/bash

cd ./tools/

subfinder -d $1 -o ./$1_subPort.txt && python3 cloudflare-filter.py -f $1_subPort.txt
rm $1_subPort.txt

file=$1_subPort.txt_ip.txt
if [ -f "$file" ]; then
    if [ "$2" = "small" ]; then
    masscan -iL $1_subPort.txt_ip.txt --rate 1000 -p 0-10000 -oL $1_result.txt
    rm $1_subPort.txt_ip.txt
    fi
    
    if [ "$2" = "medium" ]; then
    masscan -iL $1_subPort.txt_ip.txt --rate 1000 -p 0-30000 -oL $1_result.txt
    rm $1_subPort.txt_ip.txt
    fi

    if [ "$2" = "full" ]; then
    masscan -iL $1_subPort.txt_ip.txt --rate 1000 -p 0-65500 -oL $1_result.txt
    rm $1_subPort.txt_ip.txt
    fi
else
    echo "Target is Cloudflare Protected" > $1_result.txt
fi