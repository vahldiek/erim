#!/bin/bash
# Finds all ELF objects in directory
# Arguments
# $1 - directory to search for ELF Objects
# $2 - output file
# Output: 
# Sorted list: <file size> <file name>
file -N $1/* | grep ELF | cut -d ":" -f 1 | xargs ls -S | xargs du -h > $2
