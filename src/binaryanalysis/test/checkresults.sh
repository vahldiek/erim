#!/bin/bash

# $1 file

sucRw=`grep 'numWRPKRU>0' split_wrpkru.erim.ea | wc -l`

if [ "$sucRw" != "1" ]
then
    echo "Check result failed for $1"
    exit 1;
else
    echo "$1: Successful"
fi
