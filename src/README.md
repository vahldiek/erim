# Sources of ERIM Project

Sources in this folder do not only include ERIM's sources, but also
sources to run benchmarks.

## ERIM

Includes the implementation of ERIM and its tests. More details on
ERIM's API can be found [here](erim/README.md). 

## BinaryAnalysis

Includes the static binary analysis and rewriting tool to eliminate
unsafe WRPKRU and XRSTOR instances. 

## Common

Includes commonly used defines for timers and statistics.

## TEM (Trusted-only Execute Memory)

Allow only trusted components to create execute only memory. We
provide two techniques (ptrace or LSM-based)

## scanSpeed and switchSpeed

Two microbenchmarks to test the speed of scanning pages for unsafe WRPKRU/XRSTOR
and the tests to calculate the avg. switch speed using different hardware technologies.

## Nginx

Includes the sources for nginx (version 1.12.1) sources with additional
hooks for ERIM statistics and linking liberim.

## Openssl

Includes Openssl (version 1.1.1) sources in two versions. Native
describes an unmodified version of Openssl, whereas erimized includes
the changes to isolate AES keys in a separate memory domain and only
enable access, when executing the inner cryptographic functions.

## MemSentry and nginx-memsentry

Includes a reference to the MemSentry isolation framework and
a modified nginx build to use memsentry.

## Dune

Includes a reference to the Dune prototype.

## Levee

Includes the levee prototype version 0.2 implementing CPI/CPS. More
information can be found on their project website
[https://dslab.epfl.ch/proj/cpi/](https://dslab.epfl.ch/proj/cpi/).
