"""This module contains input filters."""

import os
import abc
import datetime
import nltk
import requests
from urllib.parse import urlparse
from collections import namedtuple

from cvejob.config import Config


def validate_cve(cve):
    """Validate given CVE against predefined list of checks.

    If any of the checks fail, the CVE should not be further processed.
    """
    checks = (
        NotUnsupportedFileExtensionCheck,
        NotUnderAnalysisCheck,
        IsSupportedGitHubLanguageCheck,
        AffectsApplicationCheck,
        IsCherryPickedCveCheck,
        NotUnexpectedSiteInReferences
    )

    if Config.get('cve_age') is not None:
        checks += (NotOlderThanCheck,)

    print([x(cve).check() for x in checks])
    return all(x(cve).check() for x in checks)


class CveCheck(object, metaclass=abc.ABCMeta):
    """Base class for all input checks."""

    def __init__(self, cve):
        """Constructor."""
        self._cve = cve

    @abc.abstractmethod
    def check(self):
        """Perform the check."""


class NotOlderThanCheck(CveCheck):
    """Check whether given CVE is not older than predefined number of days."""

    def check(self):
        """Perform the check."""
        config_age = Config.get('cve_age')
        if config_age == 0:
            return True
        now = datetime.datetime.now()
        age = now.date() - self._cve.last_modified_date.date()
        return age.days < config_age


class NotUnsupportedFileExtensionCheck(CveCheck):
    """Check whether given CVE doesn't talk about unsupported files in its description."""

    def check(self):
        """Perform the check."""
        tokens = nltk.word_tokenize(self._cve.description)
        extensions = ('.php', '.c', '.cpp', '.h')
        return not any(x for x in tokens if any(
            y for y in extensions if x.lower().endswith(y)
        ))


class NotUnderAnalysisCheck(CveCheck):
    """Check whether given CVE is not under analysis by MITRE."""

    def check(self):
        """Perform the check."""
        return bool(self._cve.configurations)


class IsSupportedGitHubLanguageCheck(CveCheck):
    """Check whether GitHub references don't point to projects written in unsupported languages."""

    def check(self):
        """Perform the check."""
        refs = self._cve.references

        def is_github_ref(url):
            """Check whether given URL points to GitHub.

            :return: tuple, (owner, repo), or None if URL is not GitHub.
            """
            parsed = urlparse(url)

            if not parsed.hostname.endswith('github.com'):
                return None

            paths = parsed.path.strip('/').split('/')
            if len(paths) < 2:
                return None

            return paths[0], paths[1]

        def is_supported_gh_language(owner, repo):
            """Check whether GitHub's (owner, repo) is written in supported language."""
            url = 'https://api.github.com/repos/{o}/{r}/languages'.format(
                o=owner, r=repo
            )

            headers = {}
            token = os.environ.get('GITHUB_TOKEN')
            if token:
                headers.update({'Authorization': 'token {token}'.format(token=token)})

            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                return False

            top_lang = ''
            top_lang_bytes = 0
            langs = response.json()
            for lang, lang_bytes in langs.items():
                if lang_bytes > top_lang_bytes:
                    top_lang_bytes = lang_bytes
                    top_lang = lang
            if top_lang.lower() == Config.get('ecosystem'):
                return True
            return False

        for ref in refs:
            result = is_github_ref(ref)

            # fail here if this is a GitHub reference, but the language is not supported
            if result and not is_supported_gh_language(result[0], result[1]):
                return False

        return True


class AffectsApplicationCheck(CveCheck):
    """Check whether given CVE affects applications.

    We are not interested in operating systems and hardware.
    """

    def check(self):
        """Perform the check."""
        if self._cve.get_cpe(cpe_type='a'):
            return True
        return False


class IsCherryPickedCveCheck(CveCheck):
    """Check whether given CVE was cherry-picked by user."""

    def check(self):
        """Perform the check."""
        cve_id = Config.get('cve_id')
        if cve_id is not None:
            return cve_id == self._cve.cve_id

        return True


class NotUnexpectedSiteInReferences(CveCheck):
    """Check whether given CVE doesn't reference websites which cover other ecosystems."""

    SiteDefinition = namedtuple('SiteDefinition', ['hostname', 'path'])

    known_sites = {
        'javascript': [
            SiteDefinition(hostname='nodesecurity.io', path=None),
            SiteDefinition(hostname='snyk.io', path='/vuln/npm:'),
        ],
        'python': [
            SiteDefinition(hostname='snyk.io', path='/vuln/pip:')
        ],
        'java': [
            SiteDefinition(hostname='snyk.io', path='/vuln/maven:')
        ]
    }

    def check(self):
        """Perform the check."""
        current_ecosystem = Config.get('ecosystem')

        for ref in self._cve.references:

            ref_parsed = urlparse(ref)
            for ecosystem in self.known_sites:

                if current_ecosystem == ecosystem:
                    # all references to sites which cover currently selected
                    # ecosystem are good
                    continue

                for site in self.known_sites[ecosystem]:
                    if ref_parsed.hostname == site.hostname:
                        if site.path and not ref_parsed.path.startswith(site.path):
                            # site matches the references, but path is different,
                            # so this is not a problem
                            continue

                        # reference points to a site which covers some other ecosystem,
                        # so no reason to continue processing this CVE
                        return False

        return True
