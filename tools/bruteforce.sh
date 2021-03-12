#!/bin/bash

if [ "$1" = "critical" ]; then
    cd ./tools/
    ffuf -w ./Wordlist/critical.txt  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -sf -u https://www.$2/FUZZ -t 30 -ac -o $2_critical_temp.txt
    cat $2_critical_temp.txt | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' > $2_critical.txt
    rm $2_critical_temp.txt
    
fi

if [ "$1" = "directory" ]; then
    cd ./tools/
    ffuf -w ./Wordlist/directory.txt  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -sf -u https://www.$2/FUZZ -t 30 -ac -o $2_directory_temp.txt
    cat $2_directory_temp.txt | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' > $2_directory.txt
    rm $2_directory_temp.txt
    
fi

if [ "$1" = "customWordlist" ]; then
    cd ./tools/
    ffuf -w $2_custom_wordlist.txt -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -sf -u https://www.$2/FUZZ -t 30 -ac -o $2_custom_temp.txt
    cat $2_custom_temp.txt | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' > $2_custom.txt
    rm $2_custom_temp.txt $2_custom_wordlist.txt
    
fi


if [ "$1" = "subdomain_critical" ]; then
    cd ./tools/
    for i in `cat $2_critical_subdomain.txt` ; do ffuf -w ./Wordlist/critical.txt  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -sf -u $i/FUZZ -t 30 -ac -o $2_Criticaltemp.txt && cat $2_Criticaltemp.txt | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' >> $2_subdomain_critical.txt ; done
    rm $2_Criticaltemp.txt
    
fi

if [ "$1" = "subdomain_directory" ]; then
    cd ./tools/
    for i in `cat $2_directory_subdomain.txt` ; do ffuf -w ./Wordlist/directory.txt  -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:72.0) Gecko/20100101 Firefox/72.0" -sf -u $i/FUZZ -t 30 -ac -o $2_Directorytemp.txt && cat $2_Directorytemp.txt | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' >> $2_subdomain_directory.txt ; done
    rm $2_Directorytemp.txt
    
fi