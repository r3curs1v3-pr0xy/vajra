#!/bin/bash


if [ "$2" = "broken_links" ]; then
    blc -of --filter-level 3 -i --follow --get https://$1 | tee -a ./tools/$1_broken.txt  
    cat ./tools/$1_broken.txt | grep BROKEN > ./tools/$1_broken_links.txt
    rm ./tools/$1_broken.txt

fi

if [ "$2" = "broken_subs" ]; then
    for i in `cat ./tools/$1_brokens.txt`;do echo ==================== $i =================== >> ./tools/$1_broken_links.txt && blc -of --filter-level 3 -i --follow --get $i | grep BROKEN >> ./tools/$1_broken_links.txt;done
    rm ./tools/$1_brokens.txt

fi



if [ "$2" = "subNuclei" ]; then
    cat ./tools/$1_subdomain.txt | nuclei -t ./tools/nuclei-templates/cves/ -nC -silent >> ./tools/$1_subdomain_cve.txt

fi



if [ "$2" = "from_wayback" ]; then
    cd ./tools/
    gau $1 | tee -a $1_endpoints.txt && python2 grapX.py $1_endpoints.txt $1_extend.txt
    cat $1_extend.txt | sed '/^[[:space:]]*$/d' > $1_extensions.txt
    rm $1_extend.txt
    
fi



if [ "$2" = "include_subdomain" ]; then
    cd ./tools/
    gau -subs $1 | tee -a $1_endpointss.txt && python2 grapX.py $1_endpointss.txt $1_extends.txt
    cat $1_extends.txt | sed '/^[[:space:]]*$/d' > $1_extensionss.txt
    rm $1_extends.txt
    
fi



if [ "$2" = "rootJava" ]; then
    cd ./tools/
    gau $1 | tee -a $1_endpoint.txt
    python3 filter_js.py $1_endpoint.txt $1_tempjs.txt
    cat $1_tempjs.txt | sort -u | httpx -silent -mc 200,201,202,301,302,308 > $1_js.txt
    rm $1_tempjs.txt $1_endpoint.txt
       
fi



if [ "$2" = "subdomainJava" ]; then
    cd ./tools/
    gau -subs $1 | tee -a $1_endpointsss.txt
    python3 filter_js.py $1_endpointsss.txt $1_tempjss.txt
    cat $1_tempjss.txt | sort -u | httpx -silent -mc 200,201,202,301,302,308 > $1_jss.txt
    rm $1_tempjss.txt $1_endpointsss.txt
    
fi


if [ "$2" = "parameters" ]; then
    cd ./tools/ParamSpider/
    python3 paramspider.py -d $1 --subs False -e png,jpg,css -o $1
fi



if [ "$2" = "subParameters" ]; then
    cd ./tools/ParamSpider/
    python3 paramspider.py -d $1 -e png,jpg,css -o $1sub
fi



if [ "$2" = "cors" ]; then
   cd ./tools/
   python3 ./CORScanner/cors_scan.py -u https://$1 -t 10 -o ./Corsy/$1_cor.txt
   cd Corsy && python3 corsy.py -u https://$1 -t 10 -o $1_corsy.txt && cat *.txt > $1_cors.txt && rm $1_cor.txt
fi



if [ "$2" = "subdomainCors" ]; then
   cd ./tools/
   subfinder -d $1 | httpx -silent -follow-redirects -mc 200 > $1_cors_sub.txt
   python3 ./CORScanner/cors_scan.py -i $1_cors_sub.txt -t 10 -o ./Corsy/$1_cor.txt
   cd Corsy && python3 corsy.py -i ../$1_cors_sub.txt -t 10 -o $1_corsy.txt && cat *.txt > $1_cors.txt && rm $1_cor.txt ../$1_cors_sub.txt
fi

   
if [ "$2" = "secret" ]; then
   cd ./tools/
   for i in `cat $1_secret_subdomain.txt`; do echo ==================== $i =================== >> $1_secret.txt && python3 ./SecretFinder/SecretFinder.py -i $i -e -o cli >> $1_secret.txt ;done
   for i in `cat $1_secret_js.txt`; do echo ==================== $i =================== >> $1_secret.txt && python3 ./SecretFinder/SecretFinder.py -i $i -e -o cli >> $1_secret.txt ;done
   rm $1_secret_subdomain.txt $1_secret_js.txt
fi



    

























