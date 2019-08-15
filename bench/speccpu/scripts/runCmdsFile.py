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
        
def processInput(c):
    cmd = c.split()
#    print(cmd)
    env = os.environ.copy()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    with lock:
        print(p.communicate()[0], flush=True)
    return
            
lock = threading.RLock()
num_cores = multiprocessing.cpu_count()*2/3
if len(sys.argv) > 2:
    num_cores = int(sys.argv[2])
    
with open(sys.argv[1], 'r') as cmds:
    results = Parallel(n_jobs=num_cores)(delayed(processInput)(cmd) for cmd in cmds)
