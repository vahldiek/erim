# Benchmarking ERIM

We evaluate ERIM using the nginx web server, sqlite and node.js, and
SPECCPU with Levee.

## Nginx

When using secure web sessions, frequently accesses session keys are
created to encrypt/decrypt the traffic between the client and server.
In OpenSSL's implementation these keys are not protected and hence,
vulnerable to memory leak attacks as shown by Heartbleed. Using ERIM,
we isolate the smallest possible component inside libcrypt (one of the
libraries OpenSSL generates) including only the memory allocation and
cryptographic routines.

## SPECCPU with Levee

Levee protects code pointers against illicit updates by attackers.  It
implements CPI and CPS to protect these pointers. In their fastest
implementation CPI/CPS protect the pointers by allocating a randomly
located buffer and hiding the pointer to the buffer. We show the
additional overheads of isolating the pointers using ERIM.