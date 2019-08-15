#!/bin/bash

for s in "brain22" "brain23" "brain24" "brain25" "xeon-gold-0"
do
	ssh $s "killall ab"
done

ssh root@xeon-gold-1 "killall nginx"
