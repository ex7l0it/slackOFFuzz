#!/bin/bash
PATH=$PATH:/usr/local/bin:~/.local/bin:/usr/bin
cd $(dirname "$0")
python3 ./listen.py -d /home/zc/Datas -l 1 -t $1 -v > log.txt