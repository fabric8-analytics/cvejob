"""This module contains output writer which produces CVE record in VictimsDB notation."""

import os
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

    def __init__(self, cve, winner, candidates):
        """Constructor."""
        self._cve = cve
        self._winner = winner
        self._candidates = candidates

        _, year, cid = self._cve.cve_id.split('-')
        self._year_dir = 'database/{e}/{y}/'.format(
            e=Config.get('ecosystem'),
            y=year
        )
        self._cve_no = cid
        self._cve_id = '{y}-{n}'.format(y=year, n=cid)

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

            refs = '    - '.join([x + '\n' for x in self._cve.references])
            description = self._cve.description

            others = []
            for result in self._candidates:
                other_str = "# " + result['score'] + ' ' + result['package']
                others.append(other_str)

            affected = self._get_affected_section()
            cvss = self._cve.impact.baseMetricV2.cvssV2.baseScore

            data = self.template.format(
                cve_id=self._cve_id,
                package_name=self._winner['package'],
                cvss=cvss,
                description=description,
                refs=refs,
                affected=affected,
                others='\n'.join(others))
            f.write(data)

    def _get_affected_section(self):
        if Config.get('ecosystem') == 'java':
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
