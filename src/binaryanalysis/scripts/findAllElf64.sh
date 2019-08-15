#!/bin/bash

#$1 folder to search in
#$2 file lists files with ELF 64-bit

cat /dev/null > $2

find $1 -type f -exec file -F " " {} \; | cut -d " " -f 1,3,4 >$2 # | grep "ELF 64" | grep -v "\\.o" | grep -v "\\.ko" > $2
