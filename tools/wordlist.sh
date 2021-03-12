#!/bin/bash

cd ./tools/
if [ "$2" = "subdomain" ]; then
   gau -subs $1 | unfurl -u paths | tee $1.txt;
fi

if [ "$2" = "root" ]; then
   gau $1 | unfurl -u paths | tee $1.txt;
fi

sed 's#/#\n#g' $1.txt | sort -u | tee temp.txt;
cat temp.txt | grep -Ev '\.' | tee paths-$1.txt;
rm temp.txt;
rm relevant-files.txt;
rm $1.txt;