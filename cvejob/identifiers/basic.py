"""This module contains basic (naive) package name identifier."""

import re
import nltk
from nltk.tokenize import sent_tokenize
from nltk.corpus import stopwords
from collections import OrderedDict

from cvejob.utils import run_cpe2pkg
from cvejob.config import Config


class NaivePackageNameIdentifier(object):
    """Naive package name identifier.

    All words from the first sentence of a CVE description that are starting with uppercase letter
    are considered to be possible package names (minus stop words).
    """

    def __init__(self, cve):
        """Constructor."""
        self._cve = cve

    def _get_vendor_product_pairs(self):

        result = set()
        for cpe in self._cve.get_cpe(cpe_type='a'):
            result.add((cpe.vendor, cpe.product))
        return result

    def _get_candidates_from_description(self):
        """Try to identify possible package names from the description."""
        pkg_name_candidates = set()

        sentences = sent_tokenize(self._cve.description)
        first_sentence = sentences[0] if sentences else ''
        names = self._guess_from_sentence(first_sentence)
        pkg_name_candidates.update(set(names))
        return pkg_name_candidates

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

        regexp = re.compile('[A-Z][A-Za-z0-9-:]*')
        suspects = regexp.findall(sentence)

        results = [x.lower() for x in suspects if x.lower() not in stop_words]
        # get rid of duplicates, but keep order
        results = list(OrderedDict.fromkeys(results))
        return results

    def identify(self):
        """Identify possible package name candidates."""
        vp_pairs = self._get_vendor_product_pairs()
        desc_candidates = self._get_candidates_from_description()

        ecosystem = Config.ecosystem
        if ecosystem == 'java':
            vendor = [x[0] for x in vp_pairs] + list(desc_candidates)
        else:
            vendor = [ecosystem]
        product = [x[1] for x in vp_pairs] + list(desc_candidates)

        return run_cpe2pkg(vendor, product)
