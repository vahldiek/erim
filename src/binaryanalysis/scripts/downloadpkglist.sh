#!/bin/bash
cd pkgs
count=0
for package in `cat ../../$1`
do
    ret=1
    trials=0
    until [ $ret -eq 0 ] || [ $trials -gt 3 ]; do
	if [ $trials -gt 0 ]; then
	    echo "retry $trials"
	fi
	apt-get download $package
	ret=$?
	trials=$((trials+1))
    done
    if [ "$?" -eq "0" ]; then
	count=$((count+1))
    fi
    echo $count
done
