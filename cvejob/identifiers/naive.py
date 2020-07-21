"""This module contains basic (naive) package name identifier."""

import re

import nltk
from nltk.tokenize import sent_tokenize
from nltk.corpus import stopwords
from collections import OrderedDict

from cvejob.config import Config
from cvejob import utils
from cvejob.cpe2pkg import (
    run_cpe2pkg, PackageNameCandidate, build_cpe2pkg_query
)


class NaivePackageNameIdentifier(object):
    """Naive package name identifier.

    All words from the first sentence of a CVE description that are starting with uppercase letter
    are considered to be possible package names (minus stop words).
    """

    def __init__(self, doc, ecosystem, pkgfile_path, cpe2pkg_path=Config.cpe2pkg_path):
        """Initialize Constructor."""
        self.doc = doc
        self.ecosystem = ecosystem
        self.pkgfile_path = pkgfile_path
        self.cpe2pkg_path = cpe2pkg_path

    def _get_vendor_product_pairs(self):
        """Get (vendor, product) pairs from the CVE.

        :return: a set containing (vendor, product) pairs
        """
        result = set()
        for cpe in utils.get_cpe(self.doc, cpe_type='application'):

            vendor = cpe.get_vendor()[0]
            product = cpe.get_product()[0]

            result.add((vendor, product))

        return result

    def _get_candidates_from_description(self):
        """Try to identify possible package names from the description."""
        pkg_name_candidates = set()

        sentences = sent_tokenize(
            utils.get_description_by_lang(self.doc)
        )

        first_sentence = sentences[0] if sentences else ''
        names = self._guess_from_sentence(first_sentence)

        pkg_name_candidates.update(set(names))

        return pkg_name_candidates

    # noinspection PyMethodMayBeStatic
    def _guess_from_sentence(self, sentence):
        """Guess possible package name(s) from given description.

        Very naive approach. Words starting with uppercase letter
        are considered to be possible package names (minus stop words).

        Returns a list of possible package names, without duplicates.
        """
        stop_words = set()

        try:
            # Fails when no downloaded stopwords are available.
            stop_words.update(stopwords.words('english'))
        except LookupError:
            # Download stopwords since they are not available.
            nltk.download('stopwords')
            stop_words.update(stopwords.words('english'))

        # modified the logic to include keywords that have capital letter anywhere,
        # not necessarily as the first character.
        # Also, two words separated by hyphen are also important,
        # even when there are no capital letters
        regexp = re.compile('[A-Za-z0-9-:]*[A-Z][A-Za-z0-9-:]*|[A-Za-z0-9]+[-][A-Za-z0-9]+')
        suspects = regexp.findall(sentence)

        results = [x.lower() for x in suspects if x.lower() not in stop_words]
        # get rid of duplicates, but keep order
        results = list(OrderedDict.fromkeys(results))
        return results

    def identify(self):
        """Identify possible package name candidates."""
        vp_pairs = self._get_vendor_product_pairs()
        desc_candidates = self._get_candidates_from_description()

        results = []
        for vp_pair in vp_pairs:
            if self.ecosystem == 'java':
                # in java, vendor could help us to narrow down the groupId
                vendor = [*vp_pair] + list(desc_candidates)
            else:
                vendor = [self.ecosystem]
            product = [vp_pair[1]] + list(desc_candidates)

            results.extend(self._run_cpe2pkg(vendor, product))

        return results

    def _run_cpe2pkg(self, vendor, product):
        """Run cpe2pkg tool.

        :param vendor: list[str], a list of vendor strings
        :param product: list[str], a list of product strings
        :return: list[PackageNameCandidate], a list of package name candidates
        """
        query_str = build_cpe2pkg_query(vendor, product)
        output = run_cpe2pkg(query_str, self.pkgfile_path, self.cpe2pkg_path)
        return [
            PackageNameCandidate.from_cpe2pkg_output(x, self.ecosystem) for x in output if x
        ]
