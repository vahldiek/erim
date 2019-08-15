# Binary Analysis and Rewriting Tool for ERIM

Analyzes ELF64 binaries for the existance of a particular sequence
(here WRPKRU (0x0f01ef)) within executable memory and outputs information
about the place of the sequence. May also be used to rewrite
the sequence to eliminate it.

## ba_erim - the tool

Inputs:
* Binary to look at
* Sequence to search for in hex
* Disassembler to use (0 -> capstone, 1->dyninst)
* Analysis / Full (full includes analysis and rewrite)
* SEQ/XRSTOR - choose between looking for a specific sequence (seq) or XRSTOR (special case)

To run:
```
LD_LIBRARY_PATH=libs/ ba_erim <binary> <seq> <disasId> <analysis/full> <seq/xrstor>
```

### Output of ba_erim

Generates XML output to be used by Java-based analysis.

* General information about the binary.
* Instances of the sequence, the disassembly, categoration into
  intra-/inter-occurrence ...

## Analysis of ba_erim output

[analysis] is a java-based tool to analyse logs of `ba_erim` output.
It calculates sums and percentages based on which binaries included
the sequence.

## Dependencies

Most dependencies are included in libs/, but can be installed separately
as well. Then makefiles have to be changed to include these, instead of
the prebuild versions. This is just for ease of deployment on many machines.

* Dyninst
* Capstone
* libasan
* Boost
* For analysis Oracle Java JDK 
