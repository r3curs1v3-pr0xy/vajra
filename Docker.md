# Installing Vajra Using Docker

## Requirements

- Install [docker](https://www.docker.com/)
- Minimum 1 GB Ram (Recommended more than 2 GB)
- Minimum storage of 12 GB
- VPS is recommended

# Note : Make sure to run following commands as root.

## Command to download vajra image

```bash
docker pull r3curs1v3pr0xy/vajra:latest
```
## Command to run vajra container

```bash
docker run -d -p 80:80 --name vajra -it r3curs1v3pr0xy/vajra:latest \
  && docker exec -d vajra bash -c "service couchdb start; cd /vajra/ && node index.js"
 ```
  
  ## Command to remove docker container of vajra (Note: This will remove all database files that you might have created)
  
  ```bash
  docker rm vajra -f
  ```
  
  ## Backup
  
  You need to get shell inside docker instance for creating backup of your files.
  
  ```bash
  docker exec -it vajra /bin/bash
  ```
  
  after logging in follow the below url.
  Note: To backup your couchdb data, follow this [url](https://github.com/danielebailo/couchdb-dump)  
