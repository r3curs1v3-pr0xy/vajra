#!/bin/bash

if [ "$1" = "takeover" ]; then
    amass enum --passive -d $2 -silent -o ./tools/$2_takeover_amass.txt
    subfinder -d $2 -o ./tools/$2_takeover_subfinder.txt
    assetfinder -subs-only $2 > ./tools/$2_takeover_assetfinder.txt
    cd ./tools/ && cat $(ls | grep $2_takeover_ ) | sort -u > $2_final_takeover_subdomains.txt
    rm -f  $2_takeover_assetfinder.txt $2_takeover_subfinder.txt $2_takeover_amass.txt
    httpx -l $2_final_takeover_subdomains.txt -retries 3 -silent -no-color -mc 404 -o $2_takeover_subdomains.txt
    rm $2_final_takeover_subdomains.txt
    python3 sub404.py -f $2_takeover_subdomains.txt -d $2 > $2_space.txt
    cat $2_space.txt | sed '/^[[:space:]]*$/d' > $2_vuln.txt
    rm $2_takeover_subdomains.txt $2_space.txt
    
fi
