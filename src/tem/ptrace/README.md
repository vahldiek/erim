# Ptrace-based restriction of executable memory creation

Using Ptrace, we create a tracer process before starting the actual
application, which subscribes to seccomp events.  During the
initialization of the application, we LD_PRELOAD the erim library
(liberimsec.so) which in addition to ERIM's initialization also
registers a SecComp BPF filter which tests for mmap, mprotect, and
pkey_mprotect system calls where the PROT_EXEC bit is set.

## Build

Run `make` and test using `make test`

## Running an application with this protection

`erimptrace` is the executable which forks the application, registers
the tracer and tracee and execs the actual application. A typical
run is shown in the `test` folder.

In addition to the application and its arguments, we allow to specify
LD_LIBRARY_PATH before the application.

```bash
./erimtrace LD_LIBRARY_PATH=../../erim:../libtem test/test_application
```