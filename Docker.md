# Installing Vajra through Docker

## Requirements

- Install [docker](https://docs.docker.com/get-docker/)
- Minimum of 1 GB of RAM (Recommended more than 2 GB)
- Minimum storage of 12 GB
- A VPS is recommended


## Note : Make sure to run following commands as root.

### Steps to install
```
$ sudo su
# docker pull r3curs1v3pr0xy/vajra:latest (This will pull docker image of Vajra)
# docker run -d -p 80:80 --name vajra -it r3curs1v3pr0xy/vajra:latest \
  && docker exec -d vajra bash -c "service couchdb start; cd /vajra/ && node index.js"
```

**After this, Vajra is ready to run :)** You can visit your external IP if running on VPS to access Vajra.

## Usage
Add target name and select types of scan to start scanning.

**Note:** If subdomain is included in any of the scan then make sure to find subdomains before including subdomains in scans.

For more guide on usage, follow this URL: https://hackwithproxy.medium.com/introducing-vajra-an-advanced-web-hacking-framework-bd8307a01aa8

## Additional setup but it is important

After completing above steps, Vajra is ready to run but to make full use of its feature, some additional configuration is required. We need to setup telegram notification, subdomain monitor, javascript monitor and GitDorker.

**To make changes in Vajra or to add api keys, you need to get shell inside docker instance.**

 Follow this commands:
 
 ```docker ps```  (This will show container id of docker instance). Copy the container ID. 
 
 ![container](https://github.com/anas-jamal/vajra/blob/main/images/container.png)
 
 ```docker exec -it container id /bin/bash```
 
 ![docker](https://github.com/anas-jamal/vajra/blob/main/images/docker.png)
 
 Now you're inside docker instace. Add your tokens and keys to CertEagle, jsmon and GitDorker as shown in this video:
 https://www.youtube.com/watch?v=YKAKIaHYKP0
 
 You can also follow these steps: https://github.com/r3curs1v3-pr0xy/vajra/wiki/Installation#set-github-personal-access-token-for-gitdorker
 
 
 ### Command to remove docker container of vajra (Note: This will remove all database files that you might have created)
 
 ``` docker rm vajra -f ```
 
