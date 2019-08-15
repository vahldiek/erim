#!/bin/bash

#$1 - analyzed and rewritten binaries -> rw. binaries in $1/erim/*

find $1 -maxdepth 1 -type f | sort > list.files.txt
find $1/erim -maxdepth 1 -type f | sed -e 's/erim\///g' | sed -e 's/.erim//g' | sort > list.files.rw.txt

diff --suppress-common-lines list.files.txt list.files.rw.txt | grep 2016 | grep '<' | cut -d " " -f 2
