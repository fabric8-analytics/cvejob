"""This module contains default package name selector."""

import logging
from cpe import CPE

from cvejob.config import Config
from cvejob.utils import (
    get_java_versions,
    get_javascript_versions,
    get_python_versions
)


logger = logging.getLogger(__name__)


class VersionExistsSelector(object):
    """Selectors which picks winners based on existence of versions mentioned in the CVE record."""

    def __init__(self, cve, candidates):
        """Constructor."""
        self._cve = cve
        self._candidates = candidates

    def pick_winner(self):
        """Pick single winner.

        Or no winner, if all candidates fail the version check.
        """
        cpe_dicts = self._cve.get_cpe(cpe_type='a', nodes=self._cve.configurations)
        cpe_versions = self._get_cpe_versions(cpe_dicts)

        if cpe_versions:
            hit = False
            for candidate in self._candidates:
                package = candidate['package']

                # check if at least one version mentioned in the CVE exists
                # for given package name; if not, this is a false positive
                upstream_versions = self._get_upstream_versions(package)

                if cpe_versions & set(upstream_versions):
                    # exact match, great!
                    hit = True
                else:
                    # upstream versions sometime contain suffixes like '.Final', '.RELEASE', etc.,
                    # but those are ignored by NVD. try to detect such cases here.
                    # TODO: refactoring needed
                    for cpe_version in cpe_versions:
                        for upstream_version in upstream_versions:
                            if upstream_version.startswith(cpe_version):
                                if len(upstream_version) > len(cpe_version):
                                    version_suffix = upstream_version[len(cpe_version):]
                                    version_suffix = version_suffix.lstrip('.-_')
                                    if version_suffix and not version_suffix[0].isdigit():
                                        hit = True
                                        break

                if hit:
                    logger.info(
                        '{cve_id} Hit for package name: {package}'.format(
                            cve_id=self._cve.cve_id, package=package
                        )
                    )
                    return candidate

    def _get_upstream_versions(self, package):
        if Config.ecosystem == 'java':
            return get_java_versions(package)
        elif Config.ecosystem == 'python':
            return get_python_versions(package)
        elif Config.ecosystem == 'javascript':
            return get_javascript_versions(package)
        else:
            raise ValueError('Unsupported ecosystem {e}'.format(e=Config.ecosystem))

    def _get_cpe_versions(self, cpe_dicts):
        cpe_versions = set()
        for cpe in cpe_dicts:
            if cpe.versionStartIncluding is not None:
                cpe_versions.add(cpe.versionStartIncluding)
            if cpe.versionStartExcluding is not None:
                cpe_versions.add(cpe.versionStartExcluding)
            if cpe.versionEndIncluding is not None:
                cpe_versions.add(cpe.versionEndIncluding)
            if cpe.versionEndExcluding is not None:
                cpe_versions.add(cpe.versionEndExcluding)

            uri_version = CPE(cpe.cpe22Uri).get_version()
            if uri_version:
                cpe_versions.add(uri_version[0])

        return cpe_versions
