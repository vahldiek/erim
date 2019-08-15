# Restricting the creation of executable memory

For ERIM to be secure, we need to restrict untrusted applications to
never create executable memory without a trusted component checking
the memory for the WRPKRU sequence. We provide two solutions with
different performance and deployability scenarios. First, a
ptrace-based solution allows to run ERIM without modifying the kernel,
but provides a less performant solution. Second, a linux security
module (LSM) with kernel changes to provide a system call to enable the LSM
for the running process.

Depending on the deployment scenario you can choose one of them, and
do not need both. The advantage of ptrace-based technique is that it
does not require kernel modifications. On the other hand, allows the
kernel module-based technique to not require a runtime library
(libtem) for safety. All safety is provided by the kernel module and
ERIM (with an enabled syscall).


## Ptrace

The ptrace-based technique relies on ptrace to create a process
(tracer) which monitors the system calls of an ERIMized application
(tracee). To improve performance of this technique, we in addition
rely on SecComp and Berkeley Package Filter (BPF) to reduce the number
of events handed to the ptrace tracer and only watch mmap/protect
calls with the PROT_EXEC bit set.

This techniques does not require kernel changes and is supported by
kernels starting from 4.6.

The drawback of this technique is the overhead which is about 10x for
mmaps/mprotect calls with PROT_EXEC bit set. Unless the application
frequently creates executable memory, the overhead is negligible.

## Kernel Module

As an alternative for applications with frequent executable memory
creations, we provide a kernel module and kernel modifications to
directly implement TEM in the kernel. The overheads reduce to almost
not observable.

We require kernel modifications, to insert linux security module (LSM)
hooks to alter the page protection bits and monitor the singal handler.
Both did not exist previously

The kernel module implements these hooks and removes PROT_EXEC when
the untrusted component is running and disallows untrusted components
to register a segfault handler.