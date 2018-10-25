"""This module contains default package name selector."""

import itertools
import functools
import logging
import re

from nvdlib import utils

from cvejob.config import Config
from cvejob.outputs.victims import get_victims_affected_notation, get_victims_fixedin_notation
from cvejob.version import BenevolentVersion
from cvejob.utils import (
    get_java_versions,
    get_javascript_versions,
    get_python_versions,
    sort_versions
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
        safe_version_range = list()
        affected_version_range = list()

        cpe_entries = self._get_cpe_entries()

        for cpe_nodes in cpe_entries:

            if candidate:
                break

            try:
                cpe_version_ranges, p_vec = self._get_version_ranges(cpe_nodes)
            except TypeError:
                # TODO: try to work with list of versions from 'affected' entry
                logger.debug(
                    "[{cve_id}] Unable to find version range for cpes: {cpe_nodes}".format(
                        cve_id=self._cve.id_,
                        cpe_nodes=utils.rgetattr(cpe_nodes, 'cpe')
                    )
                )
                continue

            cpe_versions = list()
            ops = dict()

            for version_range in cpe_version_ranges:
                _, op, version = re.split(r"([<>=]{,2})", version_range)

                ops[version] = op
                cpe_versions.append(version)

            if cpe_versions:

                for candidate in self._candidates:
                    package = candidate['package']

                    hit, upstream_versions, version_repl = self.evaluate_package(
                        package, cpe_versions
                    )
                    logger.debug(
                        "[{cve_id}] Upstream versions found: {versions}".format(
                            cve_id=self._cve.id_, versions=upstream_versions
                        )
                    )

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

                        safe_versions = self._get_safe_versions(
                            upstream_versions,
                            affected_versions
                        )

                        logger.debug(
                            "[{cve_id}] Safe versions: {versions}".format(
                                cve_id=self._cve.id_, versions=safe_versions
                            )
                        )

                        safe_version_range = get_victims_notation(
                            safe_versions,
                            v_min,
                            v_max,
                        )

                        break

                    candidate = None

        return candidate, affected_version_range, safe_version_range

    def evaluate_package(self, package, cpe_versions):
        """Evaluate package w.r.t given cpe versions.

        This method checks whether a package is suitable candidate.
        """
        hit = False

        # check if at least one version mentioned in the CVE exists
        # for given package name; if not, this is a false positive
        upstream_versions = self._get_upstream_versions(package)
        benevolent_upstream_versions = {
            BenevolentVersion(x) for x in upstream_versions
        }
        benevolent_cpe_versions = {BenevolentVersion(x) for x in cpe_versions}

        upstream_match = benevolent_cpe_versions & benevolent_upstream_versions
        version_repl = {
            ver: repl
            for ver, repl in zip(upstream_match, upstream_match)
        }

        if len(version_repl) == len(cpe_versions):
            # exact match for all the versions, great!
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

        return hit, upstream_versions, version_repl

    def _get_cpe_entries(self):
        """Get CPE entries from configurations node."""
        entries = list()

        for entry in self._doc.configurations.nodes:
            entries.append(utils.rgetattr(entry, 'data'))

        return entries

    @staticmethod
    def _get_version_ranges(node):
        """Get version ranges in a suitable format."""
        version_ranges = utils.rgetattr(node, 'version_range')

        p_vec = [
            len(v_range)
            for v_range in version_ranges
        ]

        # flatten version_ranges
        version_ranges = list(itertools.chain(*version_ranges))

        return version_ranges, p_vec

    @staticmethod
    def _get_upstream_versions(package):
        """Get upstream versions for a given package and ecosystem."""
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
        """Get list of affected upstream versions."""
        # list of versions which satisfies the condition
        version_subsets = list()

        for cpe_ver, op in version_ranges.items():

            up_ver = version_repl.get(cpe_ver, cpe_ver)

            subset = list(filter(
                # use negative filtering
                lambda _v: eval(
                    "BenevolentVersion(_v) {} BenevolentVersion('{}')".format(op, up_ver)
                ),
                upstream_versions
            ))

            if subset:
                version_subsets.append(subset)

        affected_versions = list()

        idx = 0
        for p_idx in p_vec:
            subset = version_subsets[idx:idx + p_idx]
            if not subset:
                continue

            affected = functools.reduce(
                set.intersection, map(set, subset)
            )

            if affected:
                affected_versions.append(sort_versions(affected))

            idx += p_idx

        return affected_versions

    @staticmethod
    def _get_safe_versions(upstream_versions: list,
                           affected_versions: list):
        """Get list of safe upstream versions."""
        safe_version_subset = list()

        for version_subset in affected_versions:
            lo, hi = version_subset[0], version_subset[-1]

            idx = upstream_versions.index(lo)

            safe_versions = upstream_versions[:idx]
            if safe_versions:
                safe_version_subset.append(safe_versions)

            next_idx = upstream_versions.index(hi) + 1
            upstream_versions = upstream_versions[next_idx:]

        # add whats left
        safe_version_subset.append(upstream_versions)

        return safe_version_subset
