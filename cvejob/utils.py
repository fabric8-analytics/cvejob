"""This module contains helper functions."""

import calendar
import datetime
import re

import logging

import itertools as it

from cpe import CPE

from nvdlib.utils import rgetattr


logger = logging.getLogger(__name__)


def get_cpe(doc, cpe_type: str = None) -> list:
    """Get list of CPE objects.

    :param doc: Document, single Document object from Collection
    :param cpe_type: str, <type>
        <type>: any of (or abbreviation of) [application, hardware, operating_system]
    """
    valid_cpe_types = ['application', 'hardware', 'operating_system']
    if cpe_type and not isinstance(cpe_type, str):
        raise TypeError(f"`cpe_type` expected to be str, got: {type(cpe_type)}")

    type_to_check = None

    if cpe_type is not None:
        for t in valid_cpe_types:
            if t.startswith(cpe_type.lower()):
                type_to_check = t
                break

        if cpe_type and type_to_check is None:
            raise ValueError(
                f"`cpe_type` expected to be any of {valid_cpe_types}"
            )

    cpe_str_list = rgetattr(doc, 'configurations.nodes.data.cpe') or []

    if not any(cpe_str_list):
        cpe_list = []

    else:
        cpe_list = [
            CPE(cpe_str) for cpe_str in it.chain(*[x for x in cpe_str_list if x is not None])
        ]

        if type_to_check:
            cpe_list = list(filter(
                lambda _cpe: eval(f"_cpe.is_{type_to_check}()"),
                cpe_list
            ))

    return cpe_list


def get_description_by_lang(doc, lang='en'):
    """Get description for given language."""
    desc_data = rgetattr(doc, 'cve.descriptions.data')
    desc = None

    for node in desc_data:
        # if no lang value, assume english
        if getattr(node, 'lang', 'en') == lang:
            desc = getattr(node, 'value', None)
            break

    return desc


def parse_date_range(range_string: str):
    """Parse date range string.

    valid examples:
        - date_range="YYYY/MM/DD-YYYY/MM/DD"
        - date_range="YYYY/MM/-YYYY/MM/"
        - date_range="YYYY//-YYYY//"
    """
    valid_date_pattern = r"^(?P<year>[\d]{4})/(?P<month>[\d]{2})?/(?P<day>[\d]{2})?$"
    matcher = re.compile(valid_date_pattern)

    range_from, range_to = range_string.split(sep='-')

    match_from = matcher.match(range_from)
    match_to = matcher.match(range_to)

    if not all([match_from, match_to]):
        raise ValueError(
            ("Date range '{range_string}' does not match expected format.\n"
             "\tExpected format: r'{valid_date_pattern}'").format(
                range_string=range_string,
                valid_date_pattern=valid_date_pattern
            ))

    def parse_year(s):
        return int(s)

    def parse_month(s, sub):
        return int(s) if s else sub

    def parse_day(s, year, month, sub='first'):
        default = [calendar.monthrange(year, month)[1], 1][sub == 'first']

        return int(s) if s else default

    # This is not a pretty way of parsing the date,
    # but we need to fill in missing values for month and day differently
    year_from = parse_year(match_from.group('year'))
    month_from = parse_month(match_from.group('month'), sub=1)
    day_from = parse_day(match_from.group('day'), year_from, month_from, 'first')

    date_from = datetime.datetime(year_from, month_from, day_from)

    year_to = parse_year(match_to.group('year'))
    month_to = parse_month(match_to.group('month'), sub=12)
    day_to = parse_day(match_to.group('day'), year_to, month_to, 'last')

    date_to = datetime.datetime(year_to, month_to, day_to)

    return date_from, date_to
