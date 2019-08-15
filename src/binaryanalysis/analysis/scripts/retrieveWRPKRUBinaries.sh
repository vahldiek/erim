#!/bin/bash

# $1 input sumary file containg string FUll list of Objects with WRPKRU:
# $2 output into file

tail -n +`grep -n "Full list of rewriteable PKRU:" $1 | cut -d ":" -f 1` $1 > $2
