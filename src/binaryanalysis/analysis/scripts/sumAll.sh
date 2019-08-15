#!/bin/bash

for dis in debian8 ubuntu14 ubuntu16 gentoo gentoogold
do
	for flag in seq xrstor
	do
		./scripts/erim_analysis.sh ../results/ $dis.$flag
	done
done
