#!/bin/bash

#$1 folder of pkgs
#$2 folder to store extracted package
#program assumes $1 only holds .deb files
#and extracts all of them to $2

for pkg in `ls $1`
do
    mkdir -p $2/$pkg
    dpkg -x $1/$pkg $2/$pkg
done
