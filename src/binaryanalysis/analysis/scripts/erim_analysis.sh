#!/bin/bash

#$1 = folder of binary analysis and results

./scripts/analyze.sh $1/analysisElf64.$2.txt $1/summary.$2.txt
./scripts/retrieveWRPKRUBinaries.sh $1/summary.$2.txt $1/wrpkrubinaries.$2.txt
