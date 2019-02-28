"""Module for processing and interpreting NVD version ranges.

The easiest way how to use this module is call `get_ranges_from_cve()`
function.
"""

import nvdlib.utils
from nvdlib.model import Document
from cpe import CPE
from enum import Enum
import re
import operator

from f8a_version_comparator.comparable_version import ComparableVersion
from cvejob.version import BenevolentVersion
from f8a_utils.versions import (
    get_versions_for_maven_package, get_versions_for_pypi_package, get_versions_for_npm_package
)


def get_ranges_from_cve(cve, package, ecosystem):
    """Get version ranges for given CVE.

    :param cve: nvdlib.model.Document, Document object encapsulating CVE information
    :param package: str, package name
    :param ecosystem: str, ecosystem name

    :return: list of affected version ranges, list of unaffected version ranges
    """
    if not cve or not isinstance(cve, Document):
        raise ValueError('"cve" must be a nvdlib.model.Document')
    if not package or not isinstance(package, str):
        raise ValueError('"package" must be a non-empty string')
    if not ecosystem or not isinstance(ecosystem, str):
        raise ValueError('"ecosystem" must be a non-empty string')

    nodes = get_configuration_nodes(cve)
    cve_ranges = []
    for node in nodes:
        for version_range in node:
            version_ranges = get_version_ranges(version_range)
            if version_ranges:
                cve_ranges.append(VersionRange.from_range_list(version_ranges))
    upstream_versions = get_upstream_versions(package, ecosystem)
    classified_versions = classify_versions(upstream_versions, cve_ranges)
    affected = get_affected_ranges(classified_versions)
    safe = get_safe_ranges(classified_versions)
    return affected, safe


class ClassifiedVersion(object):
    """Version classified as affected or unaffected.

    TODO: if Python 3.7: turn into a data class
    """

    def __init__(self, version, is_affected=False):
        """Instantiate ClassifiedVersion.

        :param version: str, version
        :param is_affected: bool, indicator whether the version is affected or not
        """
        self.version = version
        self.is_affected = is_affected

    def __str__(self):
        return '{version}({status})'.format(version=self.version, status=self.is_affected)

    def __repr__(self):
        return 'ClassifiedVersion({version}, {status})'.format(
            version=self.version, status=self.is_affected
        )


def get_configuration_nodes(cve, apps_only=True):
    """Get configuration nodes from given CVE object.

    :param cve: nvdlib.model.Document, Document object encapsulating CVE information
    :param apps_only: bool, only return configuration nodes affecting application, or all nodes
    :return: [[str],[str]], list of lists of affected version ranges (as strings)
    """
    nodes = list()

    for configuration in cve.configurations.nodes:
        data = nvdlib.utils.rgetattr(configuration, 'data')

        if apps_only:
            for node in data:
                if CPE(node.cpe).is_application():
                    break
            else:
                continue

        nodes.append(nvdlib.utils.rgetattr(configuration, 'data'))

    return nodes


def get_version_ranges(nodes):
    """Get version ranges from configuration nodes.

    :param nodes: list of configuration nodes as returned from get_configuration_nodes()
    :return list[str], list of version range strings
    """
    return nvdlib.utils.rgetattr(nodes, 'version_range') or []


class VersionOperator(Enum):
    """Enum for version range operators.

    Following operators are currently supported: '==', '<=', '>=', '<', '>'.
    """

    EQ = '=='
    LE = '<='
    GE = '>='
    LT = '<'
    GT = '>'


class VersionSpec(object):
    """Version specification.

    Version bundled with VersionOperator.
    """

    def __init__(self, version_str, operator_str):
        """Instantiate VersionSpec."""
        self.version = version_str
        self.operator = VersionOperator(operator_str)

    def contains(self, version_str, cmp_class=ComparableVersion):
        """Check if `version_str` is in the version spec.

        :param version_str: str, version to check
        :param cmp_class: class used to compare given version against version spec
        """
        this_version = cmp_class(self.version)
        other_version = cmp_class(version_str)

        op_map = {
            VersionOperator.EQ: operator.eq,
            VersionOperator.LE: operator.ge,
            VersionOperator.GE: operator.le,
            VersionOperator.LT: operator.gt,
            VersionOperator.GT: operator.lt
        }

        op_func = op_map.get(self.operator)
        if not op_func:
            raise ValueError('Unsupported operator {op}'.format(op=str(self.operator)))

        return op_func(this_version, other_version)

    @classmethod
    def from_str(cls, version_spec):
        """Build VersionSpec from version specification string.

        :param version_spec: str, version specification (e.g.: '<=1.0')
        """
        _, op, version = re.split(r"([<>=]{1,2})", version_spec)
        return cls(version, op)

    def __str__(self):
        return self.operator.value + self.version

    def __eq__(self, other):
        return self.operator == other.operator

    def __ne__(self, other):
        return not self.__eq__(other)

    # operators which enclose the right side of the version range are considered greater
    def __gt__(self, other):
        ops = (VersionOperator.LE, VersionOperator.LT)
        return self.operator in ops and other.operator not in ops

    def __lt__(self, other):
        ops = (VersionOperator.GE, VersionOperator.GT)
        return self.operator in ops and other.operator not in ops

    def __ge__(self, other):
        return self.operator == other.operator or self.__gt__(other)

    def __le__(self, other):
        return self.operator == other.operator or self.__lt__(other)


class VersionRange(object):
    """Version range."""

    def __init__(self, boundary_1, boundary_2=None):
        """Instantiate VersionRange object."""
        self.boundary_1 = VersionSpec.from_str(boundary_1)
        if boundary_2 is None:
            boundary_2 = boundary_1
        self.boundary_2 = VersionSpec.from_str(boundary_2)

    def contains(self, version_str, cmp_class=ComparableVersion):
        """Check if `version_str` is in the range.

        :param version_str: str, version to check
        :param cmp_class: class used to compare given version against the range
        """
        return (
            self.boundary_1.contains(version_str, cmp_class=cmp_class) and
            self.boundary_2.contains(version_str, cmp_class=cmp_class)
        )

    @classmethod
    def from_range_list(cls, range_list):
        """Build VersionRange object from a list of CVE ranges.

        :param range_list: list[str], list of CVE ranges as returned from get_version_ranges()
        """
        return cls(*range_list)

    @classmethod
    def from_list(cls, versions_list, is_right_closed=False, is_left_closed=False):
        """Build VersionRange object from a list of versions.

        :param versions_list: list[str], sorted list of versions
        :param is_right_closed: bool, whether the version list interval is right-closed or not
        :param is_left_closed: bool, whether the version list interval is left-closed or not
        """
        upper_str = None
        lower_str = None

        if not is_right_closed and not is_left_closed:
            raise ValueError('Interval is not closed from either side.')

        if is_right_closed:
            upper_str = VersionOperator.LE.value + versions_list[-1]

        if is_left_closed:
            lower_str = VersionOperator.GE.value + versions_list[0]

        if is_right_closed and is_left_closed:
            return cls(upper_str, lower_str)
        elif is_right_closed:
            return cls(upper_str)
        else:
            return cls(lower_str)

    def __str__(self):
        if self.boundary_1 == self.boundary_2:
            return '{hi}'.format(hi=self.boundary_1)
        elif self.boundary_1 < self.boundary_2:
            return '{hi},{lo}'.format(hi=self.boundary_2, lo=self.boundary_1.version)
        else:
            return '{hi},{lo}'.format(hi=self.boundary_1, lo=self.boundary_2.version)

    def __repr__(self):
        return 'VersionRange({r})'.format(r=str(self))


def classify_versions(upstream_versions, version_ranges):
    """Classify versions as affected and unaffected.

    :param upstream_versions: list[str], list of upstream versions
    :param version_ranges: list[[VersionRange]], list of CVE version ranges

    :return: list[ClassifiedVersion] sorted list of classified upstream versions
    """
    sorted_upstream_versions = [ComparableVersion(x) for x in upstream_versions]
    sorted_upstream_versions.sort()

    # list of sorted upstream versions represented as "classified versions",
    # all versions are unaffected by default
    classified_versions = [ClassifiedVersion(x.version, False) for x in sorted_upstream_versions]

    for classified_version in classified_versions:
        benev_upstream_version = BenevolentVersion(classified_version.version)

        for version_range in version_ranges:
            if version_range.contains(benev_upstream_version.exact, cmp_class=BenevolentVersion):
                # the version is within the range so it is affected, mark it as such
                classified_version.is_affected = True
                break

    return classified_versions


def get_affected_ranges(classified_versions):
    """Get version ranges for affected versions.

    :param classified_versions: [ClassifiedVersion], sorted list of classified versions
    :return: list of VersionRange objects
    """
    unaffected_found = False
    affected_list = []

    ranges = []

    def append_range(affected_versions):
        if affected_versions:
            ranges.append(
                VersionRange.from_list(
                    affected_versions, is_left_closed=unaffected_found, is_right_closed=True
                )
            )

    # iterate over the sorted list of the upstream versions
    for version_tuple in classified_versions:

        # we found an unaffected version, all previously encountered affected versions form a range
        if not version_tuple.is_affected:
            append_range(affected_list)

            # all ranges/intervals will be closed from both sides from now on
            unaffected_found = True
            affected_list.clear()
        else:
            affected_list.append(version_tuple.version)

    # append remaining safe versions as one final range
    append_range(affected_list)

    return ranges


def get_safe_ranges(classified_versions):
    """Get version ranges for unaffected versions.

    :param classified_versions: [ClassifiedVersion], sorted list of classified versions
    :return: list of VersionRange objects
    """
    affected_found = False
    safe_list = []

    ranges = []

    def append_range(safe_versions):
        if safe_versions:
            ranges.append(
                VersionRange.from_list(
                    safe_versions, is_left_closed=True, is_right_closed=affected_found
                )
            )

    # iterate over the sorted list of the upstream versions, in reversed order
    for classified_version in reversed(classified_versions):

        # we found a affected version, all previously encountered unaffected versions form a range
        if classified_version.is_affected:
            append_range(safe_list)

            # all ranges/intervals will be closed from both sides from now on
            affected_found = True
            safe_list.clear()
        else:
            safe_list.insert(0, classified_version.version)

    # append remaining safe versions as one final range
    append_range(safe_list)

    return ranges


def get_upstream_versions(package, ecosystem):
    """Get upstream versions for a given package and ecosystem.

    :param package: str, package name
    :param ecosystem: str, ecosystem name
    :return list[str], list of upstream versions for given package
    """
    if not package or not isinstance(package, str):
        raise ValueError('"package" must be a non-empty string')
    if not ecosystem or not isinstance(ecosystem, str):
        raise ValueError('"ecosystem" must be a non-empty string')

    eco_map = {
        'java': get_versions_for_maven_package,
        'python': get_versions_for_pypi_package,
        'javascript': get_versions_for_npm_package
    }

    get_versions = eco_map.get(ecosystem)
    if not get_versions:
        raise ValueError('Unsupported ecosystem {e}'.format(e=ecosystem))

    return get_versions(package)
