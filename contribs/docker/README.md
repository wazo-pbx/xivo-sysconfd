Dockerfile for XiVO sysconfd

## Install Docker

To install docker on Linux :

    curl -sL https://get.docker.io/ | sh
 
 or
 
     wget -qO- https://get.docker.io/ | sh

## Build

To build the image, simply invoke

    docker build -t xivo-sysconfd github.com/xivo-pbx/xivo-sysconfd.git

Or directly in the sources in contribs/docker

    docker build -t xivo-sysconfd .
  
## Usage

To run the container, do the following:

    docker run -d -P xivo-sysconfd

On interactive mode :

    docker run -i -t xivo-sysconfd /bin/bash

After launch xivo-sysconfd-service in /root directory.

    cd /root
    ./xivo-sysconfd-service

## Infos

- Using docker version 1.2.0 (from get.docker.io) on ubuntu 14.04.
- The root password is xivo by default.
- If you want to using a simple webi to administrate docker use : https://github.com/crosbymichael/dockerui

To get the IP of your container use :

    docker ps -a
    docker inspect <container_id> | grep IPAddress | awk -F\" '{print $4}'
