# Benchmark memory isolation in Levee prototype

These set of scripts evaluate different memory isolation techniques in
the Levee prototype (aka code-pointer integrity).

## SPEC CPU 2006 Benchmark

We benchmark Levee's speed by rerunning their paper's SPEC CPU 2006
experiment. SPEC CPU 2006 runs a set of scientific workloads. This
repository does not provide the sources for the SPEC 2006 Benchmark,
instead you need to buy a license.

We're using clang's test suite to compile and run the experiments.  We
configured the test suite to use the reference data set instead of the
test data set. As a result each workload takes a couple of minutes to
run, compared to a few seconds when using the test data set.

## Build benchmark

Configure the suite by setting variables in scripts/config.sh.
SPEC_SRC = location of SPEC source
USER = user which will run the benchmark - important for huge page usage

A prerequisite of the Levee prototype is to use the GOLD linker
instead of bfd.  To alter the linker, please change the link in
/usr/bin/ld to point to /usr/bin/ld.gold. Otherwise clang fails to
deploy link time optimizations.

Run `./scripts/init.sh` to initialize the environment of this
benchmark. This requires root privileges (or sudo the command), since
huge pages will be enabled.

Run `scripts/buildLevee.sh` to compile 3 levee prototypes (stored in levee*):
1) levee with ASLR
2) levee with ERIM (MPK-based isolation)
3) levee with ERIM, but simulated

Run `scripts/buildSPEC.sh` to compile all versions of SPEC with the
previously compiled levee versions and CPI or CPS. It also includes
a native version. They are stored in spec*.

## Run benchmark

```bash
scripts/runSPECLevee.sh
```

### Configuration Parameters

num_repititions - number of invocations of each benchmark

parallelism - number of parallel invocations (not advisable to go
beyond 1 if not test)

configs - spec configurations to run (e.g. cpi for ASLR-based CPI,
cpierim for ERIM-based CPI)

testsfp - list of SPEC2006 FP (floating point) benchmarks, provray breaks

testsint - list of SPEC2006 INT (integer) benchmarks, perlbench breaks

After running the script a folder called specbench-XXX (where XXX is
the date) is created with various output statistics and
configurations.

### Generated Data

Data is generated in a folder called specbench-$date. The `conf`
folder contains configuration data such as detailed information about
the machine and parameters used to run this experiment. The `json`
folder includes the raw results measured by lit in a json format.

sum.txt - Includes each workload's runtime in seconds

spec.aggsum.$conf.txt - Average workload's runtime over multiple iterations
for configuration $conf

spec.aggsum.$conf.txt.sorted - like previous, but sorted

### Broken SPEC workloads

For CPI:
perlbench & provray

For CPS:
provray
