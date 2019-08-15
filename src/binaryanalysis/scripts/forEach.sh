#!/bin/bash
# iterates over each line in $1 and executes command specified by $2-$n
filename=$1
shift
while read p; do
    tee "$p" | $1 '$2'
done <$filename
