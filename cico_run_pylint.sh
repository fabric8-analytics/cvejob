#!/bin/bash

set -ex

. cico_setup.sh
./detect-common-errors.sh
./detect-dead-code.sh
./run-linter.sh
