#!/bin/bash

# Installation from Aptitude repository
sudo curl -sL https://deb.nodesource.com/setup_14.x | sudo -E bash -;
sudo apt-get update
sudo apt-get install -y wget git tar snapd jq sed libpcap-dev curl python python-pip python3 python3-pip screen sysstat masscan nodejs software-properties-common
# GCP repository catches error when installing python, so we test if error and install with this
if [ $? != 0 ]; 
then
    sudo apt-get install -y wget git tar snapd jq sed libpcap-dev curl python2 python-pip-whl python3 python3-pip screen sysstat masscan nodejs software-properties-common
fi

echo "You are all updated now, bro!"
sudo snap install couchdb

# pip3 installation requirements
pip3 install -r requirements_pip3.txt

# pip2 installation requirements
pip2 install -r requirements_pip2.txt

# Installation from github sources
wget https://github.com/ffuf/ffuf/releases/download/v1.2.1/ffuf_1.2.1_linux_amd64.tar.gz;
tar -zxf ffuf_1.2.1_linux_amd64.tar.gz;
rm LICENSE CHANGELOG.md README.md ffuf_1.2.1_linux_amd64.tar.gz;
chmod +x ffuf && mv ffuf /bin/;
wget https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz;
tar -xzf assetfinder-linux-amd64-0.1.1.tgz;
rm assetfinder-linux-amd64-0.1.1.tgz;
chmod +x assetfinder && mv assetfinder /bin/;
wget https://github.com/lc/gau/releases/download/v1.1.0/gau_1.1.0_linux_amd64.tar.gz;
tar -zxf gau_1.1.0_linux_amd64.tar.gz;
rm gau_1.1.0_linux_amd64.tar.gz LICENSE README.md;
chmod +x gau && mv gau /bin/;
wget https://github.com/projectdiscovery/httpx/releases/download/v1.0.3/httpx_1.0.3_linux_amd64.tar.gz;
tar -zxf httpx_1.0.3_linux_amd64.tar.gz;
chmod +x httpx && mv httpx /bin/;
rm httpx_1.0.3_linux_amd64.tar.gz LICENSE README.md;
wget https://github.com/projectdiscovery/nuclei/releases/download/v2.2.0/nuclei_2.2.0_linux_amd64.tar.gz;
tar -zxf nuclei_2.2.0_linux_amd64.tar.gz;
chmod +x nuclei && mv nuclei /bin/;
rm nuclei_2.2.0_linux_amd64.tar.gz LICENSE.md README.md;
wget https://github.com/projectdiscovery/subfinder/releases/download/v2.4.6/subfinder_2.4.6_linux_amd64.tar.gz;
tar -zxf subfinder_2.4.6_linux_amd64.tar.gz;
chmod +x subfinder && mv subfinder /bin/;
rm LICENSE.md README.md subfinder_2.4.6_linux_amd64.tar.gz;
wget https://github.com/tomnomnom/unfurl/releases/download/v0.2.0/unfurl-linux-amd64-0.2.0.tgz;
tar -zxf unfurl-linux-amd64-0.2.0.tgz;
rm unfurl-linux-amd64-0.2.0.tgz;
chmod +x unfurl && mv unfurl /bin/;
cd ../tools/CRLF-Injection-Scanner/;
sudo python3 setup.py install;
cd ../;
git clone https://github.com/projectdiscovery/nuclei-templates.git;
cd ../;
cd ./tools/jsmon/;
sudo python3 setup.py install;
cd ../../;
cd ./install/;
wget https://github.com/OWASP/Amass/releases/download/v3.10.5/amass_linux_amd64.zip;
sudo apt-get install -y unzip;
unzip amass_linux_amd64.zip;
cd amass_linux_amd64 && sudo mv amass /bin/;
cd ../;
rm -r amass_linux_amd64;
rm amass_linux_amd64.zip;

# Installation from node
sudo npm install broken-link-checker -g 
npm i -S body-parser childprocess cookie-parser cradle ejs express express-rate-limit fs http jsdom jsonwebtoken path readline xterm jquery

# Couchdb configuration
sudo snap set couchdb admin=hackwithme # This doesn't always work
# sudo snap set couchdb name=couchdb@127.0.0.1 setcookie=cutter # This doesn't always work
sudo snap start couchdb
# In the case snap does not set the password at the first launch, we manually set the interface and restart couchdb
sudo sed -i 's/;port = 5984/port = 5984/g' /var/snap/couchdb/5/etc/local.ini
sudo sed -i 's/;bind_address = 127.0.0.1/bind_address = 127.0.0.1/g' /var/snap/couchdb/5/etc/local.ini
sudo sed -i 's/;admin = mysecretpassword/admin = hackwithme/g' /var/snap/couchdb/5/etc/local.ini
sudo snap restart couchdb

sudo chmod +x ../tools/*

echo "[+] Vajra is now installed"
