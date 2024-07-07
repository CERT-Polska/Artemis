#!/bin/bash

cd $(dirname $0)

if [ ! -d venv ]; then
    python3 -m venv venv
fi

pip install --quiet -r requirements.txt

python3 slow_pusher.py $@
