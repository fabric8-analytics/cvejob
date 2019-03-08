#!/bin/bash

set -ex

here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

. ${here}/cico_setup.sh

make -f ${here}/Makefile build-cpe2pkg
#make -f ${here}/Makefile test

yum -y install docker
systemctl start docker


build_image
push_image

