#!/bin/sh

if [[ -z $1 ]] || [[ -z $2 ]]; then
	echo "usage: $0 commit repo[:tag]"
	exit 1
fi

( cd ../../; \
	git archive --format=tgz --prefix=shinano/ -o contrib/docker/shinano.tar.gz $1 )
docker build -t $2 .
