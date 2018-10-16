"""This module contains output writer which produces CVE record in VictimsDB notation."""

import os

from nvdlib import utils
from nvdlib.model import Document

from cvejob.config import Config


class VictimsYamlOutput(object):
    """Output writer which produces CVE record in VictimsDB notation."""

    TEMPLATE_DIR = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "templates/"
    )

    def __init__(self,
                 ecosystem: str,
                 cve_doc: Document,
                 winner: dict,
                 candidates: list,
                 affected_versions: list,
                 fixedin: list):
        """Constructor."""
        self._ecosystem = ecosystem

        self._doc = cve_doc
        self._cve = self._doc.cve
        self._winner = winner
        self._candidates = candidates

        self._affected_versions = affected_versions
        self._fixedin = fixedin or ['<unknown>']  # TODO

        template_path = os.path.join(self.TEMPLATE_DIR, self._ecosystem)

        with open(template_path, 'r') as f:
            self._template = f.read()

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

    def write(self):
        """Generate VictimsDB YAML file."""
        os.makedirs(self._year_dir, exist_ok=True)

        with open(os.path.join(self._year_dir, '{id}.yaml'.format(id=self._cve_no)), 'w') as f:

            refs = utils.rgetattr(self._cve, 'references.data.url')

            description = "\n".join(utils.rgetattr(self._doc, 'cve.descriptions.data.value'))

            candidate_scores = []
            for result in self._candidates:
                score_str = "{package}: {score}".format(
                    package=result['package'],
                    score=result['score']
                )
                candidate_scores.append(score_str)

            if self._ecosystem == 'java':
                gid, aid = self._winner['package'].split(':')
            else:
                gid, aid = None, None

            cvss_score = self._doc.impact.cvss.base_score

            data = self._template.format(
                cve=self._cve_id,
                name=self._winner['package'],
                cvss_v2=cvss_score,
                description=description,
                references=self.format_list(*refs),
                groupId=gid,
                artifactId=aid,
                version=self.format_list(*self._affected_versions, indent=2),
                fixedin=self.format_list(*self._fixedin, indent=2),
                candidate_scores=self.format_list(*candidate_scores,
                                                  indent=1,
                                                  comment=True)
            )

            f.write(data)

    @staticmethod
    def format_list(*args, indent=1, comment=False) -> str:
        indent = '\t' * indent
        comment = "# " if comment else ""

        formated_list = [
            "{comment}{indent} - {arg}".format(
                comment=comment,
                indent=indent,
                arg=arg
            )
            for arg in args
        ]

        return "\n".join(formated_list)


def get_victims_notation(affected_versions, v_min, v_max) -> list:
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
                version_range_str = "=={}".format(*affected_range)

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
