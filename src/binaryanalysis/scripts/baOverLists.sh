#!/bin/bash

for flag in seq xrstor
do
	for list in debian8 ubuntu14 ubuntu16 gentoo gentoogold
	do
	    scripts/binAnalysisOverFile.py $1$list.txt $flag > $2$list.$flag.txt &
	done
done	
