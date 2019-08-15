#!/bin/bash

LD_LIBRARY_PATH=$1 chrt --fifo 99 ${@:2}
