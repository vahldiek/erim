# LWC ERIM API

Instead of relying on ERIM for isolation, use light-weight
contexts (lwCs) which use a process-like abstraction to isolate
memory into several context in the same process.

## Prerequesits

To build and run this part of ERIM, you need a FreeBSD installation
with the kernel changes from lwC and in [makefile](makefile) set
the correct path to the userspace library.

More information on how to install lwC can be found here:
http://www.cs.umd.edu/projects/lwc/

