#!/bin/bash

set -e
set -x

docker run -ti --rm -v $(pwd):/cvejob/:z -v $(pwd)/nvdlib/nvdlib:/usr/lib/python3.6/site-packages/nvdlib $@ fabric8-analytics/cvejob python3.6 run.py
