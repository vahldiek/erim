#!/usr/bin/python

from __future__ import print_function

import sys
import subprocess
import threading
from joblib import Parallel, delayed
import multiprocessing
import os

if sys.version_info[:2] < (3, 3):
        old_print = print
        
def print(*args, **kwargs):
        flush = kwargs.pop('flush', False)
        old_print(*args, **kwargs)
        file = kwargs.get('file', sys.stdout)
        if flush and file is not None:
                file.flush()
        
def processInput(binary):
        path = binary.split()[0]
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = 'libs/'
        p = subprocess.Popen(["../../bin/binaryanalysis/ba_erim", path, "0F01EF", "1", "analysis", sys.argv[2]], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        out=p.communicate()
        with lock:
                print(out[0], flush=True)
                if out[1]:
                        print(path, flush=True)
                        print(out[1], flush=True)
#                filelist.write(path)
#                filelist.write("\n")
#                filelist.flush()
#                if (p.returncode != 0):
#                        sys.exit()
        return 

lock = threading.RLock()
num_cores = multiprocessing.cpu_count()/8
filelist = open("listfiles.ba.txt", "w+")

with open(sys.argv[1], 'r') as toInspect:
        results = Parallel(n_jobs=num_cores)(delayed(processInput)(binary) for binary in toInspect)

filelist.close()
