#!/bin/bash

set -ex

here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

. ${here}/cico_setup.sh

make -f ${here}/Makefile build-cpe2pkg
${here}/run-tests.sh
