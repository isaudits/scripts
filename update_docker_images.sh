#!/bin/bash
# Updates all docker images on filesystem and deletes old images

#docker images | grep -v REPOSITORY | awk '{print $1}' | xargs -L1 docker pull
docker images --format "{{.Repository}}:{{.Tag}}" | xargs -L1 docker pull
docker image prune -f