#!/bin/bash

set -e
set -x

docker run -ti --rm -e CVEJOB_CVE_AGE=${CVEJOB_CVE_AGE:-1} -v $(pwd):/cvejob/:z $@ quay.io/openshiftio/fabric8-analytics-cvejob python3.6 run.py

