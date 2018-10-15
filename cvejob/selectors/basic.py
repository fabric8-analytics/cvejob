"""This module contains default package name selector."""

import re
import itertools
import logging

from nvdlib import utils

from cvejob.config import Config
from cvejob.outputs.victims import get_victims_notation
from cvejob.utils import (
    get_java_versions,
    get_javascript_versions,
    get_python_versions
)


logger = logging.getLogger(__name__)


# noinspection PyTypeChecker
class VersionExistsSelector(object):
    """Selectors which picks winners based on existence of versions mentioned in the CVE record."""

    def __init__(self, cve_doc, candidates):
        """Constructor."""
        self._doc = cve_doc
        self._cve = self._doc.cve

        self._candidates = candidates

    def pick_winner(self):
        """Pick single winner.

        Or no winner, if all candidates fail the version check.
        """
        cpe_version_ranges, = utils.rgetattr(self._doc,
                                             'configurations.nodes.data.version_range')

        cpe_versions = list()
        ops = dict()

        for version_range in itertools.chain(*cpe_version_ranges):
            _, op, version = re.split(r"([<>=]{,2})", version_range)

            ops[version] = op
            cpe_versions.append(version)

        if cpe_versions:

            hit = False

            for candidate in self._candidates:
                package = candidate['package']

                # check if at least one version mentioned in the CVE exists
                # for given package name; if not, this is a false positive
                upstream_versions = self._get_upstream_versions(package)
                version_repl = list(set(cpe_versions) & set(upstream_versions))

                if len(version_repl) == len(cpe_versions):
                    # exact match, great!
                    version_repl = list(zip(version_repl, version_repl))
                    hit = True

                else:
                    # upstream versions sometime contain suffixes like '.Final', '.RELEASE', etc.,
                    # but those are ignored by NVD. try to detect such cases here.
                    for upstream_version in upstream_versions:

                        if len(version_repl) == len(cpe_versions):
                            # done
                            break

                        for cpe_version in cpe_versions:
                            if not upstream_version.startswith(cpe_version):
                                # assume both are sorted
                                break

                            if len(upstream_version) > len(cpe_version):
                                version_suffix = upstream_version[len(cpe_version):]
                                version_suffix = version_suffix.lstrip('.-_')
                                if version_suffix and not version_suffix[0].isdigit():
                                    hit = True
                                    version_repl.append(
                                        (cpe_version, upstream_version)
                                    )

                if hit:
                    logger.debug(
                        "[{cve_id}] Hit for package name: {package}".format(
                            cve_id=self._cve.id_, package=package
                        )
                    )

                    # list of versions which satisfies the condition
                    version_subsets = list()

                    for cpe_ver, up_ver in version_repl:

                        op = ops[cpe_ver]

                        subset = list(filter(
                            # use negative filtering
                            lambda v: eval("v {} '{}'".format(op, up_ver)),
                            upstream_versions
                        ))

                        if subset:
                            version_subsets.append(subset)

                    affected_versions = list()

                    for p1, p2 in itertools.combinations(version_subsets, 2):
                        intersect = set(p1) & set(p2)

                        if intersect:
                            affected_versions.append(sorted(intersect))

                    logger.debug(
                        "[{cve_id}] Affected versions: {versions}".format(
                            cve_id=self._cve.id_, versions=affected_versions
                        )
                    )

                    v_min, v_max = upstream_versions[0], upstream_versions[-1]
                    affected_version_range = get_victims_notation(
                        affected_versions,
                        v_min,
                        v_max
                    )

                    return candidate, affected_version_range

    def _get_upstream_versions(self, package):
        if Config.ecosystem == 'java':
            return get_java_versions(package)
        elif Config.ecosystem == 'python':
            return get_python_versions(package)
        elif Config.ecosystem == 'javascript':
            return get_javascript_versions(package)
        else:
            raise ValueError('Unsupported ecosystem {e}'.format(e=Config.ecosystem))
