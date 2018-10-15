"""This module contains output writer which produces CVE record in VictimsDB notation."""

import os

from nvdlib import utils

from cvejob.config import Config


class VictimsYamlOutput(object):
    """Output writer which produces CVE record in VictimsDB notation."""

    template = """---
cve: {cve_id}
title: CVE in {package_name}
description: >
    {description}
cvss_v2: {cvss}
references:
    - {refs}
affected:
{affected}

# Additional information:
# Package name candidates:
{others}
"""

    def __init__(self, cve_doc, winner, candidates, version_ranges):
        """Constructor."""
        self._doc = cve_doc
        self._cve = self._doc.cve
        self._winner = winner
        self._candidates = candidates

        self._version_ranges = version_ranges

        _, year, cid = self._cve.id_.split('-')
        self._year_dir = 'database/{e}/{y}/'.format(
            e=Config.ecosystem,
            y=year
        )
        self._cve_no = cid
        self._cve_id = '{y}-{n}'.format(y=year, n=cid)

    @property
    def winner(self):
        """Return winner."""
        return self._winner

    @property
    def candidates(self):
        """Return candidates."""
        return self._candidates

    def _makedirs(self):
        # make sure the output directory exists
        try:
            os.makedirs(self._year_dir)
        except FileExistsError:
            pass

    def write(self):
        """Generate VictimsDB YAML file."""
        self._makedirs()

        with open(os.path.join(self._year_dir, '{id}.yaml'.format(id=self._cve_no)), 'w') as f:

            refs = '    - '.join([
                x + '\n' for x in utils.rgetattr(self._cve, 'references.data.url')
            ])

            description = "\n".join(utils.rgetattr(self._doc, 'cve.descriptions.data.value'))

            others = []
            for result in self._candidates:
                other_str = "# " + result['score'] + ' ' + result['package']
                others.append(other_str)

            affected = self._get_affected_section()
            cvss_score = self._doc.impact.cvss.base_score

            data = self.template.format(
                cve_id=self._cve_id,
                package_name=self._winner['package'],
                cvss=cvss_score,
                description=description,
                refs=refs,
                affected=affected,
                others='\n'.join(others))
            f.write(data)

    def _get_affected_section(self):
        if Config.ecosystem == 'java':
            gid, aid = self._winner['package'].split(':')

            affected = """    - groupId: {gid}
      artifactId: {aid}
      version: {version}
""".format(gid=gid, aid=aid, version='<unable-to-determine>')
        else:
            affected = """    - name: {name}
      version:
        - "{version}"
""".format(name=self._winner['package'], version='<unable-to-determine>')

        return affected


def get_victims_notation(affected_versions, v_min, v_max):
    """Output victims notation for list of affected versions.

    For more information about the format: https://github.com/victims/victims-cve-db
    """
    affected_version_range = list()

    for affected_range in affected_versions:

        lo, hi = affected_range[0], affected_range[-1]

        if len(affected_range) == 1:
            if hi == v_max:
                # not fixed yet
                version_range_str = ">=" + lo

            elif lo == v_min:
                # not fixed yet
                version_range_str = "<=" + hi

            else:
                # exact version
                version_range_str = "=={}".format(affected_range)

        else:
            if lo.startswith(hi[0]):
                # same major
                version_range_str = "<={high},{low}".format(
                    high=hi, low=lo)
            else:
                if lo == v_min:
                    version_range_str = "<={high}".format(high=hi)

                else:
                    # general range -- split into two entries
                    version_range_str = ">={low}".format(low=lo)
                    affected_version_range.append(version_range_str)

                    version_range_str = "<={high}".format(high=hi)

        affected_version_range.append(version_range_str)

    return affected_version_range
