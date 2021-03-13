#!/bin/bash

if [ "$2" = "files" ]; then
    cat ./tools/$1_files_subdomain.txt | nuclei -t ./tools/nuclei-templates/exposures/ -no-color -silent >> ./tools/$1_subdomain_files.txt

fi

if [ "$2" = "panels" ]; then
    cat ./tools/$1_panels_subdomain.txt | nuclei -t ./tools/nuclei-templates/exposed-panels/ -no-color -silent >> ./tools/$1_subdomain_panels.txt

fi

if [ "$2" = "misconfigurations" ]; then
    cat ./tools/$1_misconfigurations_subdomain.txt | nuclei -t ./tools/nuclei-templates/misconfiguration/ -no-color -silent >> ./tools/$1_subdomain_misconfigurations.txt

fi

if [ "$2" = "technologies" ]; then
    cat ./tools/$1_technologies_subdomain.txt | nuclei -t ./tools/nuclei-templates/technologies/ -no-color -silent >> ./tools/$1_subdomain_technologies.txt

fi

if [ "$2" = "vulnerabilities" ]; then
    cat ./tools/$1_vulnerabilities_subdomain.txt | nuclei -t ./tools/nuclei-templates/vulnerabilities/ -no-color -silent >> ./tools/$1_subdomain_vulnerabilities.txt

fi

if [ "$2" = "tokens" ]; then
    cat ./tools/$1_tokens_subdomain.txt | nuclei -t ./tools/nuclei-templates/exposed-tokens/ -no-color -silent >> ./tools/$1_subdomain_tokens.txt

fi
