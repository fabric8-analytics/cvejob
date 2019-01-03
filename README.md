# CVEjob

CI job which tries to identify CVEs in supported ecosystems (Maven, NPM, PyPI).

Links:

* [overview](docs/overview.md)

* [how it works](docs/how_it_works.md)

* [roadmap](docs/roadmap.md)


# Running locally

## Build the docker image:

```shell
$ make docker-build
```

You only need to rebuild the image if you update project's dependencies.
Local code changes will be reflected even without rebuild.


## Download NVD data feed (optional):

This step is optional as [cvejob](https://github.com/fabric8-analytics/cvejob) automatically detects and fetches relevant feeds
 from date range or cherry-picked CVEs. If, however, whole collection of feeds
 should be examined without explicitly stating date range or cherry-picking CVEs,
 this script may come in handy.

```shell
$ ./get_nvd.sh 2018
```

The command above will download all NVD data from 2018.

## Run the tool:

### 1) Cherry-picking CVE_ID

```shell
$ ./docker-run.sh -e CVEJOB_ECOSYSTEM=javascript -e CVEJOB_CVE_ID=CVE-2018-3728
```

The command above will look for `CVE-2018-3728` in the NVD feed. If the CVE is there, it will try to map it to a package from NPM ecosystem.
Results will be stored in the `database/` directory.


### 2) Providing date range

Date range has to follow explicit notation that goes as:
`YYYY/MM/DD`

and hence must match the following regex pattern:

`r"^(?P<year>[\d]{4})/(?P<month>[\d]{2})?/(?P<day>[\d]{2})?$"`

Valid examples:
- CVEJOB_DATE_RANGE=`'2005/12/31-2006/12/31'`
- CVEJOB_DATE_RANGE=`'2005/01/-2005/12/31'`
- CVEJOB_DATE_RANGE=`'2005//-2010//'`
   
> NOTE: Both bounds are inclusive


```shell
$ ./docker-run.sh -e CVEJOB_ECOSYSTEM=javascript -e CVEJOB_DATE_RANGE="2017//-2018//"
```


### 3) Combining 1) and 2)

This is useful for optimization as [cvejob](https://github.com/fabric8-analytics/cvejob)
can check whether the cherry-picked CVE belongs to the version range in advance
and hence save processing time and resources.

```shell
$ ./docker-run.sh -e CVEJOB_ECOSYSTEM=javascript -e CVEJOB_CVE_ID=CVE-2018-3728 -e \
CVEJOB_DATE_RANGE="2017//-2018//"
```


### *) No parameters

Without any parameters, the job will search through the NVD data and look for all CVEs affecting packages in PyPI.

Currently supported ecosystems are: `javascript` (NPM), `python` (PyPI), `java` (Maven).

You can find additional configuration options in [config.py](cvejob/config.py).

### Footnotes

#### Coding standards

- You can use scripts `run-linter.sh` and `check-docstyle.sh` to check if the code follows [PEP 8](https://www.python.org/dev/peps/pep-0008/) and [PEP 257](https://www.python.org/dev/peps/pep-0257/) coding standards. These scripts can be run w/o any arguments:

```
./run-linter.sh
./check-docstyle.sh
```

The first script checks the indentation, line lengths, variable names, white space around operators etc. The second
script checks all documentation strings - its presence and format. Please fix any warnings and errors reported by these
scripts.

#### Code complexity measurement

The scripts `measure-cyclomatic-complexity.sh` and `measure-maintainability-index.sh` are used to measure code complexity. These scripts can be run w/o any arguments:

```
./measure-cyclomatic-complexity.sh
./measure-maintainability-index.sh
```

The first script measures cyclomatic complexity of all Python sources found in the repository. Please see [this table](https://radon.readthedocs.io/en/latest/commandline.html#the-cc-command) for further explanation on how to comprehend the results.

The second script measures maintainability index of all Python sources found in the repository. Please see [the following link](https://radon.readthedocs.io/en/latest/commandline.html#the-mi-command) with explanation of this measurement.

You can specify command line option `--fail-on-error` if you need to check and use the exit code in your workflow. In this case the script returns 0 when no failures has been found and non zero value instead.

#### Dead code detection

The script `detect-dead-code.sh` can be used to detect dead code in the repository. This script can be run w/o any arguments:

```
./detect-dead-code.sh
```

Please note that due to Python's dynamic nature, static code analyzers are likely to miss some dead code. Also, code that is only called implicitly may be reported as unused.

Because of this potential problems, only code detected with more than 90% of confidence is reported.

#### Common issues detection

The script `detect-common-errors.sh` can be used to detect common errors in the repository. This script can be run w/o any arguments:

```
./detect-common-errors.sh
```

Please note that only semantical problems are reported.

#### Check for scripts written in BASH

The script named `check-bashscripts.sh` can be used to check all BASH scripts (in fact: all files with the `.sh` extension) for various possible issues, incompatibilities, and caveats. This script can be run w/o any arguments:

```
./check-bashscripts.sh
```

Please see [the following link](https://github.com/koalaman/shellcheck) for further explanation, how the ShellCheck works and which issues can be detected.

