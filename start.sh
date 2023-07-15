#!/bin/bash
PATH=$PATH:/usr/local/bin:~/.local/bin:/usr/bin
cd $(dirname "$0")
python3 ./lazycrasher.py -l 1 -t $1 -v > watch.log