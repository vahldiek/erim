#!/bin/bash
source scripts/config.sh

git submodule init

# Make SPEC source available to LLVM build system.
mkdir test-suite/test-suite-externals
ln -s $SPEC_SRC test-suite/test-suite-externals/speccpu2006

groupadd hugepages
groupid=`getent group hugepages | cut -d ":" -f 3`
adduser $user hugepages

echo "vm.nr_hugepages = 4096" >>/etc/sysctl.conf
echo "vm.hugetlb_shm_group = $groupid" >> /etc/sysctl.conf

mkdir /hugepages
echo "hugetlbfs\t/hugepages\thugetlbfs\tmode=1770,gid=$groupid\t0\t0" >> /etc/fstab

sysctl -p
