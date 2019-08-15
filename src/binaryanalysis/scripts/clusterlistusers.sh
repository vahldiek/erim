#!/bin/bash

if [ "$1" = "-a" ]
then
    op=a
    servers=${@:2:$#}
elif [ "$1" = "-s" ]
then
    op=s
    servers=${@:2:$#}
else
    op=as
    servers=${@:1:$#}
fi

res=""
for s in $servers
do
    ssh $s "ps aux | grep -v -e root -e USER -e avahi -e daemon -e Debian-+ -e dnsmasq -e _lldpd -e message+ -e nslcd -e ntp -e statd | cut -d ' ' -f1" > $s.users
done

for job in `jobs -p`
do
    wait $job || let "FAIL+=1"
done

for s in $servers
do
    res="$res $s.users"
done

if [[ $op == *"a"* ]];
then
    u=`cat $res | sed 's/ /\n/g' | sort -u`
    uc=`echo $u | sed 's/ /\n/g' | wc -l`
    echo "Found $uc users on $servers"
    echo $u
    echo ""
fi

if [[ $op == *"s"* ]];
then
    for s in $servers
    do 
        echo "$s:"
        cat $s.users | sort -u
        echo ""
    done
fi
