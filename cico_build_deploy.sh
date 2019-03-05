#!/bin/bash

set -ex

here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

. ${here}/cico_setup.sh

yum -y install docker
systemctl start docker

make -f ${here}/Makefile build-cpe2pkg
make -f ${here}/Makefile test

build_image

push_image
