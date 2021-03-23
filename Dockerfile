FROM ubuntu:20.04

ADD . /app
WORKDIR /app

# we're gonna be use coachdb from 2nd container
RUN sed -i 's/127.0.0.1/couchdb/g' /app/index.js
RUN sed -i 's/curl -L https:\/\/couchdb.apache.org\/repo\/bintray-pubkey.asc | sudo apt-key add;//g' /app/install/install.sh
RUN sed -i 's/echo "deb https:\/\/apache.bintray.com\/couchdb-deb focal main" | sudo tee -a \/etc\/apt\/sources.list;//g' /app/install/install.sh
RUN sed -i 's/sudo apt update;//g' /app/install/install.sh
RUN sed -i 's/sudo apt install -y couchdb;//g' /app/install/install.sh

RUN apt-get clean
RUN apt-get update
RUN apt-get install sudo -y
RUN apt-get install wget -y
RUN chmod +x /app/tools/*
RUN chmod +x /app/install/install.sh
RUN cd /app/install && ./install.sh

