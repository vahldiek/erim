#!/bin/bash

touch content/0kb

for s in 1 2 4 8 16 32 64 128
do
	dd if=/dev/zero of=content/${s}kb bs=1k count=${s}
done
