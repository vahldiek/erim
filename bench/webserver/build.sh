#!/bin/bash

#builds nginx with specified openssl verison or build native and erimized

nginxloc=../../src/nginx
webbench=../../bench/webserver

#$1 openssl folder
build_nginx() {
    basename=`basename $1`
	
    basename=$basename$ccname	
    
    echo "building $basename"
    
    cd $nginxloc
    
    make clean
    
    ./configure "--prefix=$webbench/nginx-$basename/" --with-file-aio --without-http_rewrite_module --with-http_ssl_module "--with-openssl=$1" --with-ld-opt="$2" --with-cc-opt="-I ../erim/ -D_GNU_SOURCE" #--with-openssl-opt='-d' --with-debug
    
    make -j40 && make install
    
    cd -
}

build_nginx_clang() {
    export CC=/local/vahldiek/erim-public/src/MemSentry/clang-3.8/bin/clang
    export CXX=/local/vahldiek/erim/public/src/MemSentry/clang-3.8/bin/clang++

    ccname="clang"

    build_nginx $1 $2

}

build_nginx_memsentry() {
 
    basename=`basename $1`

    echo "building memsentry nginx"
    cd $nginxloc/../nginx-memsentry
    make clean
   
    export CC=/local/vahldiek/erim-public/src/MemSentry/clang-3.8/bin/clang 
    export CXX=/local/vahldiek/erim-public/src/MemSentry/clang-3.8/bin/clang++
    ./configure "--prefix=$webbench/nginx-mpx/" --with-file-aio --without-http_rewrite_module --with-http_ssl_module "--with-openssl=$1" --with-ld-opt="$2" --with-cc-opt="-I ../erim"

    make -j40 && make install

    export CC=""
    cd -
}

# build common and erim library
make -s -C ../../src/common
make -s -C ../../src/erim

if [ -z "$1" ]
then
    build_nginx ../openssl/native "../../bin/erim/liberim.a"
    build_nginx ../openssl/erimized "../../bin/erim/liberim.a"
    build_nginx ../openssl/vmfunc "../dune/libdune/libdune.a"
else
    if [ "mpx" = "$1" ];
    then
	build_nginx_memsentry ../openssl/native "../../bin/erim/liberim.a"
    elif [ "clang" = "$2" ];
    then
        build_nginx_clang ../openssl/$1 "../../bin/erim/liberim.a"
    elif [ "vmfunc" = "$1" ];
    then
	    build_nginx ../openssl/$1 "../dune/libdune/libdune.a"
    elif [ "erimizedsimu" = "$1" ];
    then
	    build_nginx ../openssl/$1 "../../bin/erim/liberimsimu.a"
    else	
        build_nginx ../openssl/$1 "../../bin/erim/liberim.a"
    fi	
fi
