# ERIM Library

This library provides functionality to protect and isolate a trusted
component (tc) from the remaining untrusted component (uc). Once the
tc is identified, its memory has to be isolated from accesses by the
uc. We rely on Intel's Memory Protection Keys (MPK) to enforce this
protection at runtime and update the accessible memory regions based
on which component is executing.

We differentiate between isolating the tc or the uc. We demonstrate
this difference by looking at two example isolation use cases.

When isolating a tc consisting of cryptographic keys and their
cryptographic operations, the remaining uc is far more complex and
hence, isolating the tc is simpler. Such an example can be found under
[src/openssl/erimized/crypto](src/openssl/erimized/crypto).

When isolating a uc consisting of a sqlite library and the tc consists
of node.js, then the tc is far more complex than the uc. As a result,
the uc runs in the isolated domain, while the tc runs as usual and has
also access to the untrusted domain.

## Usage scenarios

ERIM can be used at three differnt levels.

### Inlining Domain Switches

To highly optimize the call gate, one can inline the call gate into
parts of functions. API is available in
[erim_api_inlined.h](erim_api_inlined.h).

An example can be found in [testinlined](testinlined).

#### Inlined API

### Compile-time Function Overlay

Overlay API is availble in [erim_api_overlay.h](erim_api_overlay.h)
and builds call gate functions around an actual function
implementation allowing the same function to either be used as a
secure function (with call gate) or without by directly calling the
function. This is especially handy, when overlaying container
implementations which are used for secrets as well as ordenary data.

An example can be found in [testoverlay/](testoverlay/).

#### Overlay API

### Dynamic-link-time Function Overlay

Define the same function name, include the domain switches and call
the actual function.

An example can be found in [testdynlink](testdynlink).

There is no particular API for dynmic-link-time overlay.

## Library Arguments

Arguments are given via define at compilation time or in the code
before

```C
#include <erim.h>
```

<dl>
<dt>ERIM_INTERITY_ONLY</dt><dd>If defined, assures that untrusted application
 may read the memory of the trusted component.

If undefined, assures that the untrusted application may never read or
 write the trusted component. (providing confidentiality and
 integrity)</dd>

<dt>ERIM_ISOLATE_UNTRUSTED</dt><dd>If defined, trusted runs in
domain 0. (application runs in domain 1)

If undefined, trusted runs in domain 1. (application runs in domain 0)
Without changes everything runs in domain 0 including libc.

When the tc needs to take control over libc, it also needs to run in
domain 0. When the tc only protects a small and limited set of
functions which do not require libc access (e.g. the cryptographic
functions of OpenSSL), then the tc can run in domain 1 without
chainging the app.</dd>

<dt>SIMULATE_PKRU</dt> <dd>If defined, emulates the cost of WRPKRU
  instruction.

If undefined, uses RD/WRPKRU.</dd>

<dt>ERIM_STATS</dt><dd>Adds code to count the number of switches in a global variable. Print counter by calling `erim_printStats()`</dd>

<dt>ERIM_DBG</dt><dd>Adds print statements to switch calls and initilization code</dd>
</dl>

## Library Initialization

The simplest possible library initialization includes a setup of the
shared memory allocator, calling into the OS to define the trusted
domain (depending on ERIM_ISOLATE_UNTRUSTED), scanning the memory for
rouge WRPKRU and switching to the trusted/untrusted domain.

```C
erim_init(shmemSize);
erim_memScan(NULL, NULL, ERIM_UNTRUSTED_PKRU);
erim_switch_to_trusted/untrusted;
```
### Isolating Untrusted Components

In addition, especially when untrusted code is isolated, an entire
library can be moved to the isolated domain to ensure the libraries
variables are still available after the call gate to the untrusted
domain.

## Isolated shared memory allocator

ERIM provides an isolated shared memory allocator in
[erim_shmem.h](erim_shmem.h). This allows ERIM to transparently overly
functions like malloc, realloc, calloc, free and switch between the
isolated memory allocator (when running in the isolated domain) and
the regular libc malloc.

## Statistics

When statistics are enabled by adding ERIM_STATS before including
[erim.h](erim.h), call gates automatically count the number of WRPKRU
instructions. The number can be printed using `erim_printStats()` or
by accessing the `erim_cnt` variable (unsigned long long).

ERIM does not provide independent statistics for each call gate.

## Todo's

* Multi-threading for stack swapping 