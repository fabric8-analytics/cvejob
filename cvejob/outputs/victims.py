"""This module contains output writer which produces CVE record in VictimsDB notation."""

import os

from nvdlib import utils
from nvdlib.model import Document

from cvejob.config import Config
from cvejob.cpe2pkg import PackageNameCandidate


class VictimsYamlOutput(object):
    """Output writer which produces CVE record in VictimsDB notation."""

    TEMPLATE_DIR = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "templates/"
    )

    def __init__(self,
                 ecosystem: str,
                 cve_doc: Document,
                 winner: PackageNameCandidate,
                 candidates: list,
                 affected: list,
                 fixedin: list):
        """Initialize Constructor."""
        self._ecosystem = ecosystem

        self._doc = cve_doc
        self._cve = self._doc.cve
        self._winner = winner
        self._candidates = candidates

        self._affected_versions = affected
        self._safe_versions = fixedin

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
                    package=result.package,
                    score=result.score
                )
                candidate_scores.append(score_str)

            if self._ecosystem == 'java':
                gid, aid = self._winner.package.split(':')
            else:
                gid, aid = None, None

            cvss_score = self._doc.impact.cvss.base_score

            data = self._template.format(
                cve=self._cve_id,
                name=self._winner.package,
                cvss_v2=cvss_score,
                description=description,
                references=self.format_list(*refs),
                groupId=gid,
                artifactId=aid,
                version=self.format_list(*self._affected_versions, indent=2, quote=True),
                fixedin=self.format_list(*self._safe_versions, indent=2, quote=True)
            )

            f.write(data)

    @staticmethod
    def format_list(*args, indent=1, comment=False, quote=False) -> str:
        """Format list to yaml ouptut."""
        indent_str = ' ' * (indent * 4)
        comment = "# " if comment else ""

        arg_template = '{arg}'
        if quote:
            arg_template = '"' + arg_template + '"'

        if args:
            line_template = '{comment}{indent}- ' + arg_template

            formated_list = [
                line_template.format(
                    comment=comment,
                    indent=indent_str,
                    arg=arg
                )
                for arg in args
            ]
        else:
            # empty list
            formated_list = ['{indent}[]'.format(indent=indent_str)]

        return "\n".join(formated_list)
