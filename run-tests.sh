#!/usr/bin/bash

set -e
set -x

COVERAGE_THRESHOLD=80

export TERM=${TERM:-xterm}
if [ "$TERM" = "dumb" ]; then
    # likely running in CI, just force "xterm"
    export TERM=xterm
fi

# set up terminal colors
NORMAL=$(tput sgr0)
RED=$(tput bold && tput setaf 1)
GREEN=$(tput bold && tput setaf 2)
YELLOW=$(tput bold && tput setaf 3)

function find_python() {
    # we want tests to run on python3.6
    printf 'checking alias `python3.6` ... ' >&2
    PYTHON=$(which python3.6 2> /dev/null) || :
    if [ -z "$PYTHON" ]; then
        printf "%s\"python3.6\" NOT FOUND%s\n" "${YELLOW}" "${NORMAL}" >&2

        printf 'checking alias `python3` ... ' >&2
        PYTHON=$(which python3 2> /dev/null) || :

        [ -z "$PYTHON" ] && printf "${RED} \"python3\" NOT FOUND ${NORMAL}\n" && return 1
    fi

    printf "%sOK%s\n" "${GREEN}" "${NORMAL}" >&2

}
# make sure that PYTHON environment variable is populated
find_python

function prepare_venv() {
    ${PYTHON} -m venv "venv" && source venv/bin/activate
}

[ "$NOVENV" == "1" ] || prepare_venv || exit 1


# install the project
${PYTHON} -m pip install -r requirements.txt

# install test dependencies
${PYTHON} -m pip install -r tests/requirements.txt

# download nltk data
${PYTHON} -c "import nltk; nltk.download('words')"
${PYTHON} -c "import nltk; nltk.download('punkt')"
${PYTHON} -c "import nltk; nltk.download('stopwords')"

# ensure pytest and coverage is available
${PYTHON} -m pip install pytest pytest-cov

# run tests
${PYTHON} -m pytest --cov="cvejob/" --cov-report term-missing --cov-fail-under=$COVERAGE_THRESHOLD -vv tests/ $@

`which codecov` --token=e27b6fe8-371b-41d9-9894-8d32af762c19
