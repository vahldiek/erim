# TEM Kernel module

The TEM kernel module is implemented as an LSM module in [lsm](lsm).
In order to run, we need the additional kernel hooks provided
in the modified linux kernel (see modifiedlinux-4.9.110.tar.gz).

## Requirements

We only tested this against Debian 8. Other distributions may work as
well, but require additional steps.

## Build

Build the linux kernel from source by following Debian's description:
https://www.debian.org/releases/stable/i386/ch08s06.html.en

```
apt-get install kernel-package
tar xvfz modifiedlinux-4.9.110.tar.gz
cd linux-4.9.110
make menuconf
fakeroot make-kpkg --initrd --revision=1.0.custom kernel_image -j`grep -c ^processor /proc/cpuinfo`
sudo dpkg -i ../linux-image-4.9-*.deb
sudo shutdown -r now
```

Build the kernel module implementing TEM:

```
cd lsm
make
```
Test both the kernel and LSM by running `make test` in [test](test)

## Run TEM kernel module and ERIMizied applications

```
sudo insmod lsm/tem_lsm.ko
Start ERIMized application (make sure rim_init() is called with
  ERIM_TEM_KM and not ERIM_TEM_PTRACE)
```

## Modifications of the kernel

All modifications are contained in the following files:
* security/security.c

* include/linux/lsm_hooks.c

* mm/mmap.c

* mm/mprotect.c

* arch/x86/entry/syscalls/syscall_64.tbl