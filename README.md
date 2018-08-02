# CVEjob

CI job which tries to identify CVEs in supported ecosystems (Maven, NPM, PyPI).


# Running locally

## Build the docker image:

```shell
$ make docker-build
```

You only need to rebuild the image if you update project's dependencies.
Local code changes will be reflected even without rebuild.


## Download NVD data feed:

```shell
$ ./get_nvd.sh 2018
```

The command above will download all NVD data from 2018.

## Run the tool:

```shell
$ ./docker-run.sh -e CVEJOB_ECOSYSTEM=javascript -e CVEJOB_CVE_ID=CVE-2018-3728
```

The command above will look for `CVE-2018-3728` in the NVD feed. If the CVE is there, it will try to map it to a package from NPM ecosystem.
Results will be stored in the `database/` directory.

Without any parameters, the job will search through the NVD data and look for all CVEs affecting packages in PyPI.

Currently supported ecosystems are: `javascript` (NPM), `python` (PyPI), `java` (Maven).

You can find additional configuration options in [config.py](cvejob/config.py).

