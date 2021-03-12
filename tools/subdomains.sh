#!/bin/bash

if [ "$1" = "amass" ]; then
    amass enum --passive -d $2 -silent -o ./tools/$2_amass.txt
    httpx -l ./tools/$2_amass.txt -retries 3 -silent -no-color -mc 200,302 -o ./tools/$2_valid_resolve.txt
    httpx -l ./tools/$2_amass.txt -status-code -retries 3 -silent -ip -title -no-color -o ./tools/$2_resolve.txt
    rm ./tools/$2_amass.txt
    python3 ./tools/arrange.py -f ./tools/$2_resolve.txt && rm ./tools/$2_resolve.txt
fi

if [ "$1" = "subfinder" ]; then
    subfinder -d $2 -o ./tools/$2_subfinder.txt
    httpx -l ./tools/$2_subfinder.txt -retries 3 -silent -no-color -mc 200,302 -o ./tools/$2_valid_resolve.txt
    httpx -l ./tools/$2_subfinder.txt -status-code -retries 3 -silent -ip -title -no-color -o ./tools/$2_resolve.txt
    rm ./tools/$2_subfinder.txt
    python3 ./tools/arrange.py -f ./tools/$2_resolve.txt && rm ./tools/$2_resolve.txt
fi

if [ "$1" = "assetfinder" ]; then
    assetfinder -subs-only $2 > ./tools/$2_assetfinder.txt
    httpx -l ./tools/$2_assetfinder.txt -retries 3 -silent -no-color -mc 200,302 -o ./tools/$2_valid_resolve.txt
    httpx -l ./tools/$2_assetfinder.txt -status-code -retries 3 -silent -ip -title -no-color -o ./tools/$2_resolve.txt
    rm ./tools/$2_assetfinder.txt
    python3 ./tools/arrange.py -f ./tools/$2_resolve.txt && rm ./tools/$2_resolve.txt
fi

if [ "$1" = "all" ]; then
    amass enum --passive -d $2 -silent -o ./tools/$2_all_amass.txt
    subfinder -d $2 -o ./tools/$2_all_subfinder.txt
    assetfinder -subs-only $2 > ./tools/$2_all_assetfinder.txt
    cd ./tools/ && cat $(ls | grep $2_all_ ) | sort -u > $2_final_subdomains.txt
    rm -f  $2_all_assetfinder.txt $2_all_subfinder.txt $2_all_amass.txt
    httpx -l $2_final_subdomains.txt -retries 3 -silent -no-color -mc 200,302 -o $2_final_valid_subdomains_resolve.txt
    httpx -l $2_final_subdomains.txt -status-code -retries 3 -silent -ip -title -no-color -o $2_final_subdomains_resolve.txt
    python3 arrange.py -f $2_final_subdomains_resolve.txt && rm $2_final_subdomains.txt $2_final_subdomains_resolve.txt
    
fi



