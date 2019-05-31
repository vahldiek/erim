# ERIM: Secure, Efficient In-Process Memory Isolation using Intel MPK

This repository holds the sources to the ERIM project from [MPI-SWS](https://www.mpi-sws.org).
We describe the system to isolate secrets in our
USENIX Security'19 paper and demonstrate the performance. A pre-print is available on arXiv
([https://arxiv.org/pdf/1801.06822.pdf](https://arxiv.org/pdf/1801.06822.pdf)) describing
an earlier version of ERIM and its performance.

We're currently in the process of cleaning up the code and will release it by the time
of the conference. In case you'd like to have access immediately, please contact [Anjo](mailto:anjovahldiek@gmail.com).

<!--

The sources of the ERIM library are in [src/erim](src/erim). We provide several
tests that demonstrate the library's use. In this release we also
provide the ptrace and linux security module-based technique to
restrict an untrusted component's capability to mmap/mprotect
executable memory. You can find those in [src/tem](src/tem).
Our binary analysis and rewriting tool can be found in [src/binaryanalysis](src/binaryanalysis).
Additionally we provide the benchmarks and scripts to run them in [bench](bench).

-->

## Abstract

Isolating sensitive data and state can increase the security and
robustness of many applications.  Examples include protecting
cryptographic keys against exploits like OpenSSL's Heartbleed bug or
protecting a language runtime from native libraries written in unsafe
languages. When runtime references across isolation boundaries occur
relatively infrequently, then page-based hardware isolation can be
used, because the cost of kernel- or hypervisor-mediated domain
switching is tolerable. However, some applications, such as isolating
cryptographic session keys in a network-facing application or
isolating frequently invoked native libraries in managed runtimes,
require very frequent domain switching. In such applications, the
overhead of kernel- or hypervisor-mediated domain switching is
prohibitive.

In this paper, we present ERIM, a novel technique that provides
hardware-enforced isolation with low overhead, even at high switching
rates (ERIM's average overhead is less than 1\% for 100,000
switches per second).  The key idea is to combine memory protection
keys (MPKs), a feature recently added to Intel CPUs that allows
protection domain switches in userspace, with binary inspection to
prevent circumvention. We show that ERIM can be applied with little
effort to new and existing applications, doesn't require compiler
changes, can run on a stock Linux kernel, and has low runtime overhead
even at high domain switching rates.

<!--

## Build

Run `make` in [src/](src/) to compile the ERIM library.

To further  build specific benchmarks  or applications, look  into the
[bench](bench) folder.

## ERIMizing Applications and Libraries

For an application or library to make use of ERIM, the developer needs to
alter an application at three key points.

* ERIM's initialization needs to run before the application's start by, for
instance, LD_PRELOADing a shared library (with an appropiate init function)
or statically linking ERIM and calling the initialization functions. All
initialization is provided by liberim (see [src/erim](src/erim)).

* After deviding the application into a trusted and an untrusted
component, insert the appropriate switches using the API provided in
[src/erim](src/erim). Dividing an application may be done by hand, automatically
by a compiler or supervised using stub generators.

* When running an ERIMized application, we need to hinder all untruted
components from creating executable memory. This is achieved using one
of the two trusted-only execute memory (TEM) techniques provided in
[src/tem](src/tem).

Most of the overhead of running ERIM, stems from the switches, since
they appear frequently. Both, the initialization and TEM, result in
non-negligible overhead, but their functionality is invoked
infrequently.

## Compatibility

ERIM requires a CPU supporting Intel Memory Protection Keys (MPK) and
a Linux Kernel supporting MPK. We have tested and run our evaluation on
Debian 8 (kernel version 4.9.60 or 4.9.110) using Intel Xeon Scalable Silver and
Gold (6142) CPUs.

-->