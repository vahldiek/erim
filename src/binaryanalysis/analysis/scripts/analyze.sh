#!/bin/bash

#$1 = binary analysis file name
#$2 = output filename

java -classpath "bin/:../javalibs/*" org.mpi.erim.AnalyzeBinaryAnalysis $1 > $2
