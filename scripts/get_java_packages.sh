#!/bin/bash

set -e
set -x

here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
default_packages_jar="${here}/../tools/bin/maven-packages.jar"

packages_jar=${CVEJOB_JAVA_PACKAGES_JAR:-${default_packages_jar}}

java -jar ${packages_jar} | sed 's|:|,|'

