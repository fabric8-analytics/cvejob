#!/bin/bash

set -e
set -x

# Skip opening pull requests, default: true
export CVEJOB_SKIP_PULL_REQUESTS=${CVEJOB_SKIP_PULL_REQUESTS:-true}

# Do not process CVEs older than 1 day (by default)
export CVEJOB_CVE_AGE=${CVEJOB_CVE_AGE:-1}

here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

python3.6 run.py

if [ "$CVEJOB_SKIP_PULL_REQUESTS" != "true" ]; then
    pushd ${here}
        ./open_pull_requests.sh
    popd
else
    echo "Skipping opening pull requests..."
fi

