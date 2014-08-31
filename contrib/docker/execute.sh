#!/bin/sh

if [[ -z $1 ]]; then
	echo "usage: $0 image"
	exit 1
fi

if [[ -z $(ip -6 a s docker0 scope link to fe80::/64 mngtmpaddr) ]]; then
	ip -6 a a fe80::2/64 dev docker0 mngtmpaddr
fi

ip r d 100.64.0.0/10 dev docker0
ip -6 n d fe80::1 dev docker0

container=$(docker run --privileged -d $1)
neigh=$(docker inspect -f '{{.NetworkSettings.IPAddress}}' $container)

ip r a 100.64.0.0/10 via $neigh dev docker0
ip -6 r a 64:ff9b::/96 via fe80::1 dev docker0

echo $container
