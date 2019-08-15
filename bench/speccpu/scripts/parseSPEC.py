import json
import sys

filename=sys.argv[1]

with open(filename) as data_file:
    data = json.load(data_file)
    test = data["tests"]
    for t in test:
        result = t["code"]
        name = t["name"]
        name = name[name.rfind('/')+1:name.rfind(".")]
        metrics = t["metrics"]
        exectime = metrics["exec_time"]
        
        print("%s %d %f" % (name, (1 if result=="PASS" else  0), exectime));
