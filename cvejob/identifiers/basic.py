"""This module contains basic (naive) package name identifier."""

import re

import nltk
from nltk.tokenize import sent_tokenize
from nltk.corpus import stopwords
from collections import OrderedDict

from cvejob.config import Config
from cvejob import utils


class NaivePackageNameIdentifier(object):
    """Naive package name identifier.

    All words from the first sentence of a CVE description that are starting with uppercase letter
    are considered to be possible package names (minus stop words).
    """

    def __init__(self, doc):
        """Constructor."""
        self._doc = doc

    def _get_vendor_product_pairs(self):

        result = set()
        for cpe in utils.get_cpe(self._doc, cpe_type='application'):

            vendor = cpe.get_vendor()[0]
            product = cpe.get_product()[0]

            result.add((vendor, product))

        return result

    def _get_candidates_from_description(self):
        """Try to identify possible package names from the description."""
        pkg_name_candidates = set()

        sentences = sent_tokenize(
            utils.get_description_by_lang(self._doc)
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
        results = []
        for vp_pair in vp_pairs:
            if ecosystem == 'java':
                vendor = [vp_pair[0]] + list(desc_candidates)
            else:
                vendor = [ecosystem]
            product = [vp_pair[1]] + list(desc_candidates)

            results.extend(utils.run_cpe2pkg(vendor, product))

        return results
