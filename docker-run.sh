#!/bin/bash

set -e
set -x

docker run -ti --rm -v $(pwd):/cvejob/:z $@ fabric8-analytics/cvejob python3.6 run.py
