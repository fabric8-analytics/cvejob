"""This module contains output writer which produces CVE record in VictimsDB notation."""

import os
import re

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
                 affected: list,
                 fixedin: list):
        """Constructor."""
        self._ecosystem = ecosystem

        self._doc = cve_doc
        self._cve = self._doc.cve
        self._winner = winner
        self._candidates = candidates

        self._affected_versions = affected
        self._safe_versions = fixedin or ['<unknown>']  # TODO

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
    def cve(self):
        """Return CVE object."""
        return self._cve

    @property
    def affected_versions(self):
        """Return affected versions."""
        return self._affected_versions

    @property
    def safe_versions(self):
        """Return safe versions."""
        return self._safe_versions

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
                fixedin=self.format_list(*self._safe_versions, indent=2)
            )

            f.write(data)

    @staticmethod
    def format_list(*args, indent=1, comment=False) -> str:
        """Format list to yaml ouptut."""
        indent = ' ' * (indent * 4)
        comment = "# " if comment else ""

        formated_list = [
            "{comment}{indent}- {arg}".format(
                comment=comment,
                indent=indent,
                arg=arg
            )
            for arg in args
        ]

        return "\n".join(formated_list)


def get_victims_affected_notation(affected_versions,
                                  v_min,
                                  v_max) -> list:
    """Output victims notation for list of affected versions.

    For more information about the format: https://github.com/victims/victims-cve-db
    """
    affected_version_range = list()

    for affected_range in affected_versions:

        if not affected_range:
            continue

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
            if lo == v_min:
                version_range_str = "<={high}".format(high=hi)
            else:
                version_range_str = "<={high},{low}".format(high=hi, low=lo)

        affected_version_range.append(version_range_str)

    return affected_version_range


def get_victims_fixedin_notation(safe_versions,
                                 v_min,
                                 v_max) -> list:
    """Output victims notation for a list of safe versions.

    For more information about the format: https://github.com/victims/victims-cve-db
    """
    fixedin_version_range = list()

    for safe_range in safe_versions:

        if not safe_range:
            continue

        lo, hi = safe_range[0], safe_range[-1]

        if hi == v_max:
            # fixed from the lowest version onwards
            version_range_str = ">=" + lo

        elif lo == v_min:
            # safe versions, but these were never vulnerable
            # TODO: do we really want to skip them?
            continue
        elif len(safe_range) == 1:
            # exact version
            version_range_str = "=={}".format(*safe_range)
        else:
            version_range_str = "<={high},{low}".format(high=hi, low=lo)

        fixedin_version_range.append(version_range_str)

    return fixedin_version_range


def reverse_version_string(version_string: str):
    """Reverse version string."""
    v_string = version_string

    if version_string.startswith('<'):
        v_string = '>' + version_string[1:]

    elif version_string.startswith('>'):
        v_string = '<' + version_string[1:]

    return v_string
