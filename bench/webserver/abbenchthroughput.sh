#!/bin/bash

# INPUT
# $1 - Output directory (default ./)

out=$1
if [ $# -eq 0 ]
then
    out="."
fi

#code configs
erimstat="0"

#configurations
num_ab_inst=16
num_clients=75
time=65
stat_interval=1
local_prefix=/local/vahldiek
bin_dir=$local_prefix/erim-public/bench/webserver
safeplace=/DS/erim/work/results/
remote=xeon-gold-1
url="https://$remote"
compress="yes"
num_repititions=3
ethname=eth0

# iterating config parameters
declare -a servers=("erimizedsimu")
#declare -a servers=("nativeclang" "erimizedclang" "mpx")
#declare -a servers=("native" "erimized")

declare -a files=("0kb")
#declare -a files=("0kb" "1kb" "2kb" "4kb" "8kb" "16kb")
#declare -a files=("0kb" "1kb" "2kb" "4kb" "8kb" "16kb" "32kb" "64kb" "128kb")

declare -a sessions=("100000000")

declare -a workers=("1")
#declare -a workers=("1" "3" "5" "10")

declare -a abserver=("xeon-gold-0" "brain22" "brain23" "brain24" "brain25")
#declare -a abserver=("localhost") #preferably set of machines
numabservers=${#abserver[@]}

#functions to run intermediate stuff

function run_ab {
	session_len=$1
	exp_time=$2
	num_clients=$3
	output_dir=$4
	clid=$5
	url=$6
	file=$7
	
	mkdir -p $output_dir/ab.plot

	ssh ${abserver[$c]} "rm -f $local_prefix/data.abbench.*"
	
	c=$(($clid%$numabservers))
	echo "starting ab on ${abserver[$c]}"
	ssh ${abserver[$c]} "$bin_dir/ab -k $session_len -t $exp_time -c $num_clients -n 100000000 -g $local_prefix/data.abbench.$clid  $url/$file" > $output_dir/ab.out.$clid 2>&1 &
}

function start_server {
	server=$1
	config=$2

	if [ "$server" = "lwcopenssl" ]
	then
	    ssh root@$remote "$bin_dir/start.sh $bin_dir/apilwc:$bin_dir/../../snap/libs $bin_dir/nginx-$server/sbin/nginx -c $config" &
#        elif [ "$server" = "vmfunc" ]
#	then
#	    echo "cd $bin_dir; $bin_dir/nginx-$server/sbin/nginx -c $config"
#	    ssh root@$remote "cd $bin_dir/; $bin_dir/nginx-$server/sbin/nginx -c $config" &
	else
	    ssh root@$remote "cd $bin_dir; $bin_dir/start.sh $bin_dir/../../bin/erim $bin_dir/nginx-$server/sbin/nginx -c $config" &
	fi

	sleep 1
}

function start_stat_recording {
	output_dir=$1
	exp_time=$2
	timing_interval=$3
	stattime=`echo "1/$timing_interval * ($exp_time + 2)" | bc`

	
	ssh root@$remote "vmstat $timing_interval $stattime" >$output_dir/vmstat 2>&1 &
	ssh root@$remote "mpstat -P ALL $timing_interval $stattime" >$output_dir/mpstat 2>&1 &
	ssh root@$remote "ifstat -i $ethname $timing_interval $stattime" >$output_dir/ifstat 2>&1 &
	ssh root@$remote "mpstat -I SCPU $timing_interval $stattime" >$output_dir/scpustat 2>&1 &
	ssh root@$remote "mpstat -I CPU $timing_interval $stattime" >$output_dir/cpuintstat 2>&1 &
	ssh root@$remote "mpstat -I SUM $timing_interval $stattime" >$output_dir/interruptstat 2>&1 &
	ssh root@$remote "dstat -i -n $timing_interval $stattime" >$output_dir/dstat 2>&1 &
	
	sleep $timing_interval
}

function stop_stat_recording {
    #echo stop stat recording

    ssh root@$remote "killall -9 vmstat"
}

function collect_stats {
	output_dir=$1
	conf=$2
	res_dir=$3
	rep=$4
	file=$5

	for abs in ${abserver[@]}
	do
	    scp $abs:$local_prefix/data.abbench.* $output_dir/ab.plot/
	done
	
	#get ab interval
	ls $output_dir/ab.plot/* | xargs java -classpath "abparse/bin/" ABGPSMinutes $time 30 > "$output_dir/ab-30seconds.txt"
	
	#collect erim count stats
	if [ "$conf" = "wrpkruopenssl" ] && [ "$erimstat" = "1" ]
	then
	    ssh root@$remote "killall nginx"
	    mkdir $output_dir/erim.stat
	    scp root@$remote:$local_prefix/erim/bin/bench/erim.stat* $output_dir/erim.stat/
	    numswitches=`cat $output_dir/erim.stat/erim.stat.* | awk '{sum+=$1} END { print sum}'`
	    numcomplete=`cat $output_dir/ab.out.* | grep Complete | awk '{sum+=$3} END {print sum}'`
	    echo $conf $file $worker $rep $numswitches $numcomplete $time | awk '{print $1 " " $2 " " $3 " " $4 " " $5 " " $6 " " $5/$7 " " $5/$6}' >> $res_dir/erim.sct.cnt.txt
	fi
	
	# nice req per second
	reqps=`grep "Requests per second" $output_dir/*.out.* | cut -d ':' -f 3 | awk -F '[' '{sum+=$1}END{print sum}'`
	echo " $reqps" >> $output_dir/nice_sum.txt

	grep "$numabinst 30 60 " $output_dir/ab-30seconds.txt | sed -e "s/^/$conf $file $worker $rep /" >> $res_dir/last30seconds.txt
	cat $output_dir/nice_sum.txt | sed -e "s/^/$conf $file $worker $rep /" >> $res_dir/sum.txt

	cat $output_dir/mpstat | grep Average | grep all | awk '{print $3+$5+$8}' | sed "s/^/$conf $file $worker $rep /" >> $res_dir/cpuloadrun.txt
	tail -n +3 $output_dir/ifstat | awk '{rec+=$1;sen+=$2} END {print rec " " sen " " rec/NR " " sen/NR " "}' | sed -e "s/^/$conf $file $worker $rep /" >> $res_dir/ifloadrun.txt

	# worker cpu load assumes worker in 2 4 6 8 10 12 14 16 ...
	wloadsum=0
	for w in $(seq 2 2 $(($worker*2)))
	do
	    wload=`grep " $w " $output_dir/mpstat | grep -v Average: | tail -n +30 | head -n 30 | awk '{sum+=$4+$5+$6+$7+$8+$9+$10+$11+$12} END {print sum/NR}'`
	    wloadsum=`echo $wload+$wloadsum | bc -l`
	done
	echo $conf $file $worker $rep `echo $wloadsum/$worker | bc -l` >>"$res_dir/workercpuload.txt"
}

function collect_stat_mult {
    output_dir=$1
    conf=$2
    res_dir=$3
    rep=$4
    file=$5
	
    grep "^$conf $file $worker" $res_dir/last30seconds.txt | awk '{sum += $10; sumsq += ($10)^2}  END {printf "%d %f %f %f \n", NR, sum/NR, sqrt((sumsq-sum^2/NR)/NR), sqrt((sumsq-sum^2/NR)/NR)/(sum/NR)*100}' | sed -e "s/^/$conf $file $worker /" >> $res_dir/tpt.30.$conf.txt

   avgload=`cat $res_dir/$conf-$slen-$worker-$file-*/mpstat | grep Average | grep all | awk '{sum+=$3+$5+$8} END {print (sum/NR)}'`
   cpucores=`grep -c ^processor /proc/cpuinfo`
   echo $avgload $cpucores | awk '{print $1 " " $1/(100/$2)}' | sed -e "s/^/$conf $file $worker $num_ab_inst $num_clients /" >> $res_dir/cpuload.txt

   tail -n +3 $res_dir/$conf-$slen-$worker-$file-*/ifstat | awk '{rec+=$1;sen+=$2} END {print rec/NR " " sen/NR " "}' | sed -e "s/^/$conf $file $worker /" >> $res_dir/ifload.txt 
}

function print_headers {
    echo "Configuration | file | worker |  ab insts | clients | avg. cpu load in % | avg. load in # of cores" > $res_dir/cpuload.txt
    echo "Configuration | file | worker | iteration | avg. cpu load in %" > $res_dir/cpuloadrun.txt
    echo "Configuration | file | worker | iteration | recieved (kb) | send (kb) | rec/s (kb) | sen/s(kb)" > $res_dir/ifloadrun.txt
    echo "Configuration | file | worker | rec/s (kb) | sen/s(kb)" > $res_dir/ifload.txt
    
    if [ "erimstat" = "1" ]
    then
	echo "Configuration | Filesize | worker | Index | Number of Switches | Complete Requests | Switches/s | Switches/Request" > $res_dir/erim.sct.cnt.txt
    fi
    
    
    for s in "${servers[@]}"
    do
	echo $date >$res_dir/tpt.30.$s.txt
	echo "Configuration | Filesize | worker | Iterations | Reqs/s | std.dev. | std.dev in %" >>$res_dir/tpt.30.$s.txt
    done
    
}

function sleep_exp_time {
	exp_time=$1
	for notused in $(seq 1 $(($exp_time+2)));
	do
#	    ssh root@$remote "vmstat -z" | grep -e 'lwc' >> $output_dir/lwc.stats.txt
   	    sleep 1
	done
}

function kill_servers {
    ssh root@$remote "killall -9 nginx"
    ssh root@$remote "killall -9 nginx"

    sleep 3
}

function cleanup {
    rm -f ./erim.stat*

    ssh root@$remote "rm -f $local_prefix/erim/bin/bench/erim.stat.*"
    
    for as in ${abserver[@]}
    do
	ssh $as "rm -f $local_prefix/data.abbench.*"
    done
}

function run_repetition {
    s=$1
    slen=$2
    file=$3
    worker=$4
    for rep in $(seq 1 $num_repititions)
    do
	cleanup
	
	output_dir=$(printf "%s/%s-%d-%d-%s-%02d/" $res_dir $s $slen $worker $file $rep)
	mkdir $output_dir
	
	echo "$s $file $worker $rep"
	
	start_server $s "$bin_dir/conf/nginx.conf.$worker"
	
	start_stat_recording $output_dir $time $stat_interval
	
	for clid in $(seq 1 $num_ab_inst)
	do
	    run_ab $slen $time $num_clients $output_dir $clid $url $file
	done
	
	sleep_exp_time $time
	
	#make sure everything is over
	sleep 10
	
	stop_stat_recording $output_dir
	
	collect_stats $output_dir $s $res_dir $rep $file
	
	kill_servers
    done

    #collect stats over multple repititions
    collect_stat_mult $output_dir $s $res_dir $rep $file $slen

    if [ $compress = "yes" ]
    then
	tar -c $res_dir/$s-$slen-$worker-$file-* | pbzip2 -c >$res_dir/$s-$file-$worker.tar.bz2
	rm -rf $res_dir/$s-$slen-$worker-$file-*
    fi
}



# main loop

date=`date +%Y-%m-%d_%H%M`
res_dir="$out/abbenchthroughput-$date"
mkdir $res_dir

echo "Results in $res_dir"
echo "tail -f $res_dir/run.out"

#./cleanupabtpt.sh

{
    #write config
    mkdir $res_dir/conf
    cp abbenchthroughput.sh $res_dir/conf
    conffile="$bin_dir/conf/nginx.conf"
    cp $conffile* $res_dir/conf
    scp $conffile.* root@$remote:$bin_dir/conf/
    echo "num_ab_inst=$num_ab_inst num_clients=$num_clients abserver=${abserver[@]} session=${sessions[@]} url=$url server=${servers[@]} worker=${workers[@]} files=${files[@]} time=$time stat_interval=$stat_interval num_repititions=$num_repititions" >$res_dir/conf/arguments
    echo "num_ab_inst=$num_ab_inst num_clients=$num_clients abserver=${abserver[@]} session=${sessions[@]} url=$url server=${servers[@]} worker=${workers[@]} files=${files[@]}  time=$time stat_interval=$stat_interval num_repititions=$num_repititions"
    uname -a > $res_dir/conf/scriptmachine.txt
    ssh root@$remote "uname -a" >$res_dir/conf/expmachine.txt
    git log > $res_dir/conf/git.log
    ssh root@$remote "dmidecode" >$res_dir/conf/hw
    
    print_headers
    ant -silent -f abparse
    
    for as in "${abserver[@]}"
    do
	echo "no timesync"
	#ssh root@$as "/usr/sbin/ntpd -g" &
    done

    ssh root@$remote "mount -o remount,size=5G /dev/shm && mkdir -p /dev/shm/html"
    scp content/* root@$remote:/dev/shm/html
    
    wait
    
    for worker in "${workers[@]}"
    do
	for slen in "${sessions[@]}"
	do	
	    for file in "${files[@]}"
	    do
		for s in "${servers[@]}"
		do
		    run_repetition $s $slen $file $worker
		done  
	    done
	done
    done
    cleanup
    
    echo "experiments finished, copy results to $safeplace"
    cp -ra $res_dir $safeplace
    
    date=`date +%Y-%m-%d_%H%M`
    echo "FINISHED $date"
    
} > $res_dir/run.out 2>&1
