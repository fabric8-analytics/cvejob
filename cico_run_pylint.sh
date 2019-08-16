#!/bin/bash

set -ex

# this script is copied by CI, we don't need it
rm -f env-toolkit

check_python_version() {
    python3 tools/check_python_version.py 3 6
}

. cico_setup.sh

check_python_version
./qa/detect-common-errors.sh
./qa/detect-dead-code.sh
./qa/measure-cyclomatic-complexity.sh --fail-on-error
./qa/measure-maintainability-index.sh --fail-on-error
./qa/run-linter.sh
