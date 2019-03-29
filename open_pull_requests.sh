#!/bin/bash

# Script for opening pull requests for CVEs found by cvejob.
# cvejob stores CVEs in database/ directory.
#
# Requirements:
# GITHUB_TOKEN environment variable needs to contain a GitHub token
# which will be used to make authenticated API calls that will open
# new pull requests in the upstream CVE database.
# See: https://help.github.com/en/articles/creating-a-personal-access-token-for-the-command-line

set -e

if [ -z ${GITHUB_TOKEN} ]; then
    echo "Please provide GitHub token in GITHUB_TOKEN environment variable. Exiting..."
    exit 1
fi

here="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

data=${here}/database
mkdir -p ${data}

# check if there is at least one CVE in the cvejob-local database
file_count=`find ${data} -type f -name "*.yaml" | wc -l`
if [[ ${file_count} -eq 0 ]]; then
    echo "No CVEs, no PRs :)"
    exit 0
fi
echo "${file_count} CVEs found in the cvejob-local database"

# clone/update upstream cve db
cvedb_git_url=https://github.com/fabric8-analytics/cvedb.git
cvedb=${here}/cvedb
echo "Cloning/updating the upstream database..."
git clone ${cvedb_git_url} cvedb || (
    cd ${cvedb} && \
    git checkout master &&\
    git reset --hard origin/master &&\
    git clean -f -d &&\
    git pull
)

(
    cd ${cvedb} && git remote set-url --push origin https://${GITHUB_TOKEN}@github.com/fabric8-analytics/cvedb.git
)

# copy data from the cvejob-local database to the upstream database
echo "Merging cvejob-local database with the upstream database..."
cp -r ${data}/* ${cvedb}/database/

# get list of new/modified files in the upstream database
files=$(cd ${cvedb} && git status -s -u | awk '{ print $2 }')

# iterate over all new/modified files in the upstream database and open PRs
echo "Opening pull requests..."
for f in ${files}; do
    (cd ${cvedb}
        git checkout master

        # 1234.yaml
        number_yaml=$(basename "$f")
        # 1234
        number=${number_yaml%.yaml}

        f_dir=$(dirname "$f")
        # 2019
        year=$(basename "$f_dir")
        # CVE-2019-1234
        cve_id="CVE-${year}-${number}"
        # python (ecosystem name)
        ecosystem=$(basename `dirname "$f_dir"`)

        branch_name=${cve_id}-$(date +%s)
        git checkout -b ${branch_name}
        git add "$f"
        git commit -m "Add $cve_id"
        git push -u origin ${branch_name}

        echo "Opening pull request for ${cve_id}"

        curl -X POST -H 'Content-Type: application/json' -H "Authorization: token $GITHUB_TOKEN" -d "\
        { \
            \"title\": \"[${ecosystem}] Add $cve_id\", \
            \"body\": \"\", \
            \"head\": \"${branch_name}\", \
            \"base\": \"master\" \
        } \
" https://api.github.com/repos/fabric8-analytics/cvedb/pulls
    )

done

