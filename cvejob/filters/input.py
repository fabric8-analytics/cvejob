"""This module contains input filters."""

import os
import abc
import datetime
import nltk
import requests
import logging
import re

from urllib.parse import urlparse
from collections import namedtuple
from string import punctuation

from nltk.stem import PorterStemmer

from cvejob.config import Config
from cvejob import utils


logger = logging.getLogger(__name__)


def validate_cve(cve_doc, exclude_checks=None):
    """Validate given CVE against predefined list of checks.

    If any of the checks fail, the CVE should not be further processed.

    :param cve_doc: nvdlib.model.Document object
    :param exclude_checks: iterable, list of check classes to exclude
    :return: True if all checks passed, False otherwise.
    """
    checks = [
        NotUnsupportedFileExtensionCheck,
        NotUnderAnalysisCheck,
        IsSupportedGitHubLanguageCheck,
        AffectsApplicationCheck,
        NotUnexpectedSiteInReferencesCheck
    ]

    # ignore NotOlderThanCheck if we have cherry-picked CVE
    if not Config.cve_id and Config.cve_age is not None:
        checks.insert(0, NotOlderThanCheck)

    if exclude_checks:
        for check in exclude_checks:
            try:
                checks.remove(check)
            except ValueError:
                # this is OK, check is not in the list
                pass

    results = []
    for check in checks:
        results.append((check.__name__, check(cve_doc).check()))
        if not results[-1][1]:
            # one check failed, no need to continue checking
            break

    logger.info(results)
    return results[-1][1] if results else True


class CveCheck(object, metaclass=abc.ABCMeta):
    """Base class for all input checks."""

    def __init__(self, cve_doc):
        """Constructor."""
        self._doc = cve_doc

    @abc.abstractmethod
    def check(self):
        """Perform the check."""


class NotOlderThanCheck(CveCheck):
    """Check whether given CVE is not older than predefined number of days."""

    def check(self):
        """Perform the check."""
        config_age = Config.cve_age
        if config_age == 0:
            return True
        now = datetime.datetime.now()
        age = now.date() - self._doc.modified_date.date()
        return age.days < config_age


class NotUnsupportedFileExtensionCheck(CveCheck):
    """Check whether given CVE doesn't talk about unsupported files in its description."""

    def check(self):
        """Perform the check."""
        description = utils.get_description_by_lang(self._doc)

        tokens = nltk.word_tokenize(description)
        extensions = ('.php', '.c', '.cpp', '.h', '.go')

        return not any(x for x in tokens if any(
            y for y in extensions if x.lower().endswith(y)
        ))


class NotUnderAnalysisCheck(CveCheck):
    """Check whether given CVE is not under analysis by MITRE."""

    def check(self):
        """Perform the check."""
        return bool(self._doc.configurations)


class IsSupportedGitHubLanguageCheck(CveCheck):
    """Check whether GitHub references don't point to projects written in unsupported languages."""

    lang_groups = {
        'javascript': ['typescript']
    }

    _name_whitelist_raw = ('vuln', 'vulnerability', 'poc', 'advisory', 'security', 'cve')

    def __init__(self, cve_doc):
        """Constructor."""
        super().__init__(cve_doc)

        self._stemmer = PorterStemmer()
        # regexp to split strings on punctuation
        self._punc_re = re.compile(r'[\s{}]+'.format(re.escape(punctuation)))
        self._name_whitelist = {self._stemmer.stem(x) for x in self._name_whitelist_raw}

    def is_security_project(self, owner, repo):
        """Check whether this GitHub project is likely a security project."""
        regexp = re.compile(r'[\s{}]+'.format(re.escape(punctuation)))

        # split on punctuation
        words = regexp.split(owner)
        words.extend(regexp.split(repo))

        # further split on CamelCase
        words = [
            x for y in [re.sub('([a-z])([A-Z])', r'\1 \2', w).split() for w in words] for x in y
        ]

        for word in words:
            if self._stemmer.stem(word) in self._name_whitelist:
                return True
        return False

    def check(self):
        """Perform the check."""
        refs = utils.rgetattr(self._doc, 'cve.references.data.url') or []

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

            lang_group = (Config.ecosystem, *self.lang_groups.get(Config.ecosystem, []))

            if top_lang and top_lang.lower() in lang_group:
                return True
            return False

        for ref in refs:
            result = is_github_ref(ref)

            # ignore this reference if it is a security project
            if result and self.is_security_project(result[0], result[1]):
                continue

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
        if utils.get_cpe(self._doc, cpe_type='application'):
            return True
        return False


class NotUnexpectedSiteInReferencesCheck(CveCheck):
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
        ],
        'php': [
            SiteDefinition(hostname='wpvulndb.com', path=None)
        ]
    }

    def check(self):
        """Perform the check."""
        current_ecosystem = Config.ecosystem

        refs = utils.rgetattr(self._doc, 'cve.references.data.url') or []

        for ref in refs:

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
