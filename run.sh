#!/bin/bash

if [[ $1 == "-h" ]]; then
	echo "./run.sh -b"
	echo "./run.sh"
fi
if [[ $1 == "-b" ]]; then
	A=$(( ( $(date +%s) - $(date +%s -d "14:00:00 02/14/1990") ) / (3600 * 24) ))
	docker build -t crypt-sandbox:$A .
fi
IMAGE=$(docker images --filter=reference="crypt-sandbox" --format "{{.CreatedAt}}_{{.Repository}}:{{.Tag}}" | sort | tail -1 | cut -d'_' -f2)
echo "Running $IMAGE with -v $PWD/ansible/plugins"
docker run -ti -v "$PWD"/ansible:/file-crypt/ansible $IMAGE
