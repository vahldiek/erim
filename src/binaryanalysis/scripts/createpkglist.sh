#!/bin/bash
apt-cache  dumpavail >apt-cache.txt
grep -v "Ghc-Package" apt-cache.txt | grep -v "Auto-Built-Package" > apt-cache-wo-ghc-abuild.txt
grep "Package:" apt-cache-wo-ghc.txt > packagelist.txt
cut -d ":" -f 2 packagelist.txt | sed -e 's/^[ \t]*//' >packagelist.nice.txt
cat packagelist.nice.txt | grep -v "dbg" | grep -v "dev" | grep -v "doc" >packagelist.nice.wo-dbg-dev-doc.txt
