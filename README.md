# What is CVEjob

CVEjob is an OpenShift cronjob which periodically iterates over new and recently modified entries in the [National Vulnerability Database](https://nvd.nist.gov/)
and tries to find CVEs which affect packages in currently supported language ecosystems. Supported ecosystems
are Java (Maven), JavaScript (NPM) and Python (PyPI).


# Development

Topics related to the development of CVEjob are covered in a separate [document](docs/development.md).


# Running locally

It is possible to run CVEjob locally, on a laptop.

Requirements:
* Docker
* make


## Getting the Docker image

Running locally means running CVEjob locally in a container. That is the recommended way of running it on a laptop.

When you try to run CVEjob for the first time, it will automatically download the latest image from the registry.

Or you can build the Docker image yourself (go get some coffee, it will take a while;)):

```shell
$ make docker-build
```

## Basic usage examples

```bash
$ ./local-run.sh -e GITHUB_TOKEN=<your-github-token>
```

The command above will run the CVEjob with default configuration.
It will check CVEs that were added to or modified in NVD in the last 24 hours
and it will try to find CVEs affecting packages from the default ecosystem (which is Python).

Note it is possible to omit the GitHub token, but then you may hit GitHub's API rate limit.
Generate a new GitHub token [here](https://github.com/settings/tokens).

If CVEjob finds CVEs that could affect packages from given ecosystem,
it stores them in `database/` directory.


### Specifying ecosystem and CVE ID

Ecosystem can be explicitly set on the command line. Valid ecosystems are:
* python
* java
* javascript

```bash
$ ./local-run.sh -e GITHUB_TOKEN=<your-github-token> -e CVEJOB_ECOSYSTEM=javascript -e CVEJOB_CVE_ID=CVE-2018-3728
```

The command above will try to map [CVE-2018-3728](https://nvd.nist.gov/vuln/detail/CVE-2018-3728)
to a package from "javascript" ecosystem.

Again, the results of the run will be stored in `database/` directory.


### Known package name

Mapping CVEs to packages is not a straight-forward process and there is some guessing involved.
So it is possible that some results will not be mapped correctly. However, there may be situations
when the correct package name is known in advance.
CVEjob can be then instructed to skip guessing and to generate results for provided mapping.

```bash
$ ./local-run.sh -e CVEJOB_ECOSYSTEM=javascript -e CVEJOB_CVE_ID=CVE-2018-3728 -e CVEJOB_PACKAGE_NAME=hoek
```

The command above will map given CVE ID to the given package with the name `hoek`.
Note since package name is known in advance, there was no need to provide GitHub token.
The token is otherwise used during "filtering" phase when CVEjob tries to determine
whether given CVE is a valid CVE for given ecosystem or not.


### Running on date ranges

It is also possible to run CVEjob on all CVEs from a specific date range:

```bash
$ ./local-run.sh -e CVEJOB_ECOSYSTEM=javascript -e CVEJOB_DATE_RANGE="2018/01/-2018/12/31"
```

The command above will run CVEjob on all CVEs from 2018.

Date range has to follow explicit notation that goes as `YYYY/MM/DD`.

Valid examples:
- CVEJOB_DATE_RANGE=`'2005/12/31-2006/12/31'`
- CVEJOB_DATE_RANGE=`'2005/01/-2005/12/31'`  # day can be omitted
- CVEJOB_DATE_RANGE=`'2005//-2010//'`        # month can be omitted as well


## Opening pull requests in the fabric8-analytics CVE database

When running locally, all results are also stored only locally. However, if you'd like to open pull requests in the [fabric8-analytics CVE database](https://github.com/fabric8-analytics/cvedb), it is possible to do so easily.
There is a script in the root directly that takes mapped CVEs from the `database/` directory and opens pull requests on GitHub.

```bash
GITHUB_TOKEN=<your-github-token> ./open_pull_requests.sh
```

Note you need to part of the [fabric8-analytics organization](https://github.com/fabric8-analytics) on GitHub.


# CVEjob results

As mentioned in the previous section, CVEjob stores results in the `database/` directory.
Results are in a form of YAML file. Each YAML file represents single CVE that was mapped to a package.
The YAML file contains details about the CVE, together with the package name and information
about versions that are affected and unaffected by the CVE.

The structure of the YAML file follows, for the most part, schema of the [VictimsDB documents](https://github.com/victims/victims-cve-db#the-yaml-document).

You can see examples of CVEjob YAML files in the [fabric8-analytics CVE database](https://github.com/fabric8-analytics/cvedb).
