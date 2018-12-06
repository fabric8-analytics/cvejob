#!/bin/bash

set -ex

. cico_setup.sh
./detect-common-errors.sh
./detect-dead-code.sh
./measure-cyclomatic-complexity.sh --fail-on-error
./measure-maintainability-index.sh --fail-on-error
./run-linter.sh
