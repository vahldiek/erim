#!/bin/bash

for x in debian8 ubuntu14 ubuntu16 gentoo gentoogold
do
    ./scripts/retrieveWRPKRUBinaries.sh results/$x/summary.txt results/$x/wrpkrubinaries.txt
done
