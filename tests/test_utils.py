"""Test cvejob.utils module."""

import os

import json
import unittest

from nvdlib.model import Document
from cvejob.utils import get_cpe, get_description_by_lang, parse_date_range


HERE = os.path.dirname(__file__)
SAMPLE_CVE_PATH = os.path.join(HERE, 'data/javascript-nvdcve.json')


class TestUtils(unittest.TestCase):
    """Tests for utils module."""

    def test_get_cpe(self):
        """Test `utils.get_cpe` function."""
        with open(SAMPLE_CVE_PATH) as f:
            data, = json.load(f)['CVE_Items']
            doc = Document.from_data(data)

        # default
        cpe_list = get_cpe(doc)

        self.assertEqual(len(cpe_list), 1)

        # operating_system
        cpe_list = get_cpe(doc, cpe_type='op')

        self.assertEqual(len(cpe_list), 0)

        # application
        cpe_list = get_cpe(doc, cpe_type='application')

        self.assertEqual(len(cpe_list), 1)

    def test_get_description_by_lang(self):
        """Test `utils.get_description_by_lang` function."""
        with open(SAMPLE_CVE_PATH) as f:
            data, = json.load(f)['CVE_Items']
            doc = Document.from_data(data)

        desc_en = get_description_by_lang(doc)

        self.assertTrue(desc_en)
        self.assertIsInstance(desc_en, str)

        desc_fr = get_description_by_lang(doc, lang='fr')

        self.assertIsNone(desc_fr)

    def test_parse_date_range(self):
        """Test `utils.parse_data_range` function."""
        import datetime

        valid_date_ranges = [
            "1000/11/22-2000/11/22",
            "1000/11/-2000/11/",
            "1000//-2000//",
        ]

        invalid_date_ranges = [
            "1000/11/22",
            "1000/11-2000/11",
            "1000-2000",
            "//1-//7"
        ]

        for valid in valid_date_ranges:
            date_from, date_to = parse_date_range(valid)

            self.assertTrue(date_from)
            self.assertTrue(date_to)
            self.assertIsInstance(date_from, datetime.datetime)
            self.assertIsInstance(date_to, datetime.datetime)

        for invalid in invalid_date_ranges:

            with self.assertRaises(ValueError):
                _ = parse_date_range(invalid)
