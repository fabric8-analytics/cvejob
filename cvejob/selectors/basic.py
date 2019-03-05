"""This module contains default package name selector."""

import logging

from cvejob.version import BenevolentVersion
from cvejob.version_utils import (
    get_upstream_versions, get_configuration_nodes, get_version_ranges, VersionSpec
)


logger = logging.getLogger(__name__)


class VersionSelector(object):
    """Selectors which picks winners based on existence of versions mentioned in the CVE record."""

    def __init__(self, cve, candidates, ecosystem):
        """Instantiate VersionSelector().

        :param cve: nvdlib.model.Document, Document object encapsulating CVE information
        :param candidates: list[cvejob.cpe2pkg.PackageNameCandidate],
            a list of package name candidates
        :param ecosystem: str, ecosystem name
        """
        self.cve = cve

        self.candidates = sorted(candidates)
        self.ecosystem = ecosystem

    def pick_winner(self):
        """Pick single winner.

        Or no winner, if all candidates fail the version check.
        :return: cvejob.cpe2pkg.PackageNameCandidate, or None
        """
        if not self.candidates:
            return None

        cve_versions = self.get_versions_from_cve(self.cve)
        if not cve_versions:
            # there is nothing to evaluate if there are no versions in CVE (this should be rare),
            # let's just pick the candidate with the highest score
            return self.candidates[0]
        benev_cve_versions = [BenevolentVersion(x) for x in cve_versions]

        for candidate in self.candidates:
            upstream_versions = get_upstream_versions(candidate.package, self.ecosystem)
            if not upstream_versions:
                continue
            benev_upstream_versions = [BenevolentVersion(x) for x in upstream_versions]
            if self._evaluate_package(benev_cve_versions, benev_upstream_versions):
                return candidate

    @staticmethod
    def get_versions_from_cve(cve):
        """Get a list of versions from given CVE.

        :param cve: nvdlib.model.Document, Document object encapsulating CVE information
        :return: list[VersionSpec], a list of CVE versions
        """
        nodes = get_configuration_nodes(cve)
        version_ranges = get_version_ranges(nodes)

        versions = set()

        for version_range in version_ranges:
            for rng in version_range:
                for version in rng:
                    versions.add(VersionSpec.from_str(version).version)

        return list(versions)

    @staticmethod
    def _evaluate_package(cve_versions, upstream_versions):
        """Check if there is a overlap between CVE and upstream versions.

        :param cve_versions: list[BenevolentVersion], list of CVE versions
        :param upstream_versions: list[BenevolentVersion] list of upstream versions
        :return: bool, True if intersection of the CVE and upstream versions is not empty,
            False otherwise
        """
        return bool(set(cve_versions) & set(upstream_versions))
