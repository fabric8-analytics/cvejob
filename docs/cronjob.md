# OpenShift cronjob

There is an [OpenShift template](../openshift/template.yaml) that can be used to deploy CVEjob as cronjob.

When deployed, the cronjob only handles single ecosystem. So if you need to handle all supported ecosystems,
you need to deploy it once for each ecosystem.

## Requirements

GitHub token needs be present in secrets of the project where the cronjob will be deployed.

```bash
name: cvejob
key: github_token
```

## Deployment

Deployment is pretty straight forward:

```bash
oc process -v CVEJOB_ECOSYSTEM=python -f template.yaml | oc apply -f -
```

You can control how often the cronjob should run by `CRON_SCHEDULE` parameter.
The value should be a valid cron schedule expression, for example `0 1 * * *` (run every day at 1 AM).

[https://crontab.guru](https://crontab.guru/) is your friend here :) 

If you don't want to open pull requests at the end (i.e. do a "dry run"),
you can set `CVEJOB_SKIP_PULL_REQUESTS=true`.
