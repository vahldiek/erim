# Webserver Experiment

This experiment runs a single nginx server and multiple Apache bench
instances requesting the same webpage from the nginx server. It allows
to benchmark the setup based on different files (with e.g. different
file sizes), number of workers. 

## Build

Run `./build.sh` which builds two nginx binaries. The native nginx uses
an unmodified OpenSSL, whereas the erimized nginx uses a modified
OpenSSL which isolates AES keys in a trusted memory domain and enables
accesses only when executing cryptographic functions.

## Run benchmark

The benchmark script is `./abbenchthroughput.sh`. It is currently
configured to run on everything localhost (nginx server, ab instances
and experiment server). Ideally this is all run separately and
multiple machines are used to run ab instances.

In the current configuration, the experiment runs for 1 minute and
measures the throughput of the last 30 seconds. This reduces the
variance during a warmup phase.

### Setup

This benchmark considers three types of machines: nginx server, ab
instances and an experiment server. The nginx server serves the
requests to all ab instances. Ab instances request the same webpage
from the nginx server. The experiment server runs the
`./abbenchthroughput.sh` script and coordinates the experiment and
collects all relevant statistics.

The experiment server requires root access to the nginx server, and
regular user access to the remaining servers. On all servers the
storage path is assumed to be the same. For the ab instances to work,
you also need to export this repository into the same folder
structure.

As part of its setup phase the script creates a shared memory disk in
/dev/shm to store the content of the nginx server. You can change the
location, but then you also need to update the server root in all
`conf/nginx.conf.*` files.

### Configuration Parameters

num_ab_inst - Number of total ab instances (if more than one abserver,
then ab instances are split in round robin fashion)

num_clients - Number of simulated clients per ab instance

time - Run time of experiment

stat_interval - Time in seconds until next probe for CPU/interface statistics

local_prefix - Will be used as temporary storage

bin_dir - This folder (should include nginx-* folders and a onf folder)

safeplace - After finishing the experiments, the results folder will be copied to this location

remote - Server which runs the nginx instance

compress - if "yes", compresses the results after running (otherwise multiple GB of data are generated)

num_repititions - Number of repitition per configuration

servers - Nginx server configurations (typically "native" "erimized") as created by the `build.sh` script. A folder called nginx-* should exist.

files - Array of file names, need to exist in contents

sessions - Length ofer user sessions

workers - Array with the set of nginx worker processes. This variable is used to iterate over configuration files `conf/nginx.conf.*`. Each number of worker requires its own configuration file, since the number of workers and their CPU affinity can only be configured in the nginx conf file.

abserver - Array with hosts that act as ab servers.

### Optimizing for Performance

To guarantee the best possible performance, we carefully configure the
machine and operating system. This includes:

* The configuration files in `conf` configure nginx to set the CPU
affinity for every worker. All workers should execute on the same CPU
socket. Nginx performs quite poor, when run accross sockets. Hence,
wroker CPU affinity should request cores of the same CPU socket. The
mapping of CPU to core mapping can be found in the CPU id field in
/proc/cpuinfo.

* At high rates of requests/s, the IRQ in the kernel becomes a bottle
neck.  At which point we need to set the CPU affinity of IRQ as
explained in the following article:
https://www.kernel.org/doc/Documentation/IRQ-affinity.txt 

### Generated Data

Data is generated in a folder called abbenchthroughput-$date. It includes a configuration description folder, several files summarizing each experiment's statistics and the raw data in zipped archives or folders with the format $configuration-$file-$numworker*$iteration.

#### CPU/Networkload Load Statistics

The experiment records the CPU and network load during the experimental run and
provides a summary statistics for each configuration in the following files:

cpuload*.txt - Avg. CPU load during the experiment

ifload*.txt - Avg. Network interface load ring the experimment

workercpuload.txt - Avg. CPU load of pinned nginx worker cores (this
calculation depends on the nginx.conf.* configuration files and may
break, if the worker affinity is changed.)

#### Throughput Statistics

We consider two different throughput statistics. First, the throughput
over the entire experimental run can be found for every configuration
in `sum.txt`. Second, the throughput for the last 30 seconds of the
experimental run is summarized in last30seconds.txt and averaged over
multiple runs in tpt.30.$config.txt. Typically for plotting the later
is used.

#### Special case VMFUNC/LwC related experiments

* Can only be run with 1 worker, due to multiprocess/threadding issues

* Configuration: uncomment deamon and worker/master in [conf/nginx.conf.1]

* Add CPU affinity code the [src/nginx/src/core/nginx.c] at the bginning of main():
    cpu_set_t cpu_set;
    CPU_ZERO(&cpu_set);
    CPU_SET(2, &cpu_set);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpu_set);
