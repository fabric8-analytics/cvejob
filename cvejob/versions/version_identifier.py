"""Identifier of affected and unaffected versions.

Once the package name is known, it is possible to try to identify
ranges of versions that are affected/unaffected.
"""

from cvejob.version_utils import get_ranges_from_cve


class NVDVersions(object):
    """Identifier of affected and unaffected versions."""

    def __init__(self, cve, package, ecosystem):
        """Instantiate NVDVersions.

        :param cve: nvdlib.model.Document, Document object encapsulating CVE information
        :param package: str, package name
        :param ecosystem: str, ecosystem name
        """
        self.cve = cve
        self.package = package
        self.ecosystem = ecosystem

    def run(self):
        """Return a list of affected and unaffected versions."""
        return get_ranges_from_cve(self.cve, self.package, self.ecosystem)
