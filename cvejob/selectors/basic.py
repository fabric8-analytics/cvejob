"""This module contains default package name selector."""

import itertools
import functools
import logging
import re

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
class VersionSelector(object):
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
        candidate = None
        affected_version_range = list()

        cpe_version_ranges, p_vec = self._get_version_range_from_doc(self._doc)

        if not cpe_version_ranges:
            # TODO: try to work with list of versions from 'affected' entry
            pass

        cpe_versions = list()
        ops = dict()

        for version_range in cpe_version_ranges:
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

                upstream_match = set(cpe_versions) & set(upstream_versions)
                version_repl = {
                    ver: repl
                    for ver, repl in zip(upstream_match, upstream_match)
                }

                if len(version_repl) == len(cpe_versions):
                    # exact match, great!
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
                                    version_repl[cpe_version] = upstream_version

                if hit:
                    logger.debug(
                        "[{cve_id}] Hit for package name: {package}".format(
                            cve_id=self._cve.id_, package=package
                        )
                    )

                    affected_versions = self._get_affected_versions(
                        upstream_versions,
                        ops,
                        p_vec,
                        version_repl
                    )

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

                    break

        return candidate, affected_version_range

    @staticmethod
    def _get_version_range_from_doc(doc):
        version_ranges = list()
        p_vec = list()

        for entry in doc.configurations.nodes:
            nodes = utils.rgetattr(entry, 'data')
            for node in nodes:
                v_range = node.version_range

                p_vec.append(len(v_range))
                version_ranges.extend(v_range)

        return version_ranges, p_vec

    @staticmethod
    def _get_upstream_versions(package):
        if Config.ecosystem == 'java':
            return get_java_versions(package)
        elif Config.ecosystem == 'python':
            return get_python_versions(package)
        elif Config.ecosystem == 'javascript':
            return get_javascript_versions(package)
        else:
            raise ValueError('Unsupported ecosystem {e}'.format(e=Config.ecosystem))

    @staticmethod
    def _get_affected_versions(upstream_versions: list,
                               version_ranges: dict,
                               p_vec: list,
                               version_repl: dict):
        # list of versions which satisfies the condition
        version_subsets = list()

        for cpe_ver, op in version_ranges.items():

            up_ver = version_repl.get(cpe_ver, cpe_ver)

            subset = list(filter(
                # use negative filtering
                lambda v: eval("v {} '{}'".format(op, up_ver)),
                upstream_versions
            ))

            if subset:
                version_subsets.append(subset)

        affected_subsets = list()

        for p1, p2 in itertools.combinations(version_subsets, 2):
            p1, p2 = set(p1), set(p2)
            affected = p1 & p2

            if affected:
                affected_subsets.append(affected)

        affected_versions = list()

        idx = 0
        for p_idx in p_vec:
            affected = functools.reduce(
                set.intersection, map(set, version_subsets[idx:idx + p_idx])
            )

            if affected:
                affected_versions.append(sorted(affected))

            idx += p_idx

        return affected_versions

    @staticmethod
    def _reverse_ops(ops):
        rev_ops = dict()
        split_points = list()

        for cpe_ver, op in ops:

            if op.startswith('<'):
                rev_ops[cpe_ver] = '>' + cpe_ver[2:]

            elif op.startswith('>'):
                rev_ops[cpe_ver] = '<' + cpe_ver[2:]

            else:
                # split subsets at this version
                split_points.append(cpe_ver)

        return rev_ops, split_points
