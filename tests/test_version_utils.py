"""Tests for cvejob.version_utils module."""

import pytest
from cvejob.version_utils import (
    get_configuration_nodes, VersionOperator, VersionSpec, VersionRange,
    classify_versions, get_affected_ranges, get_safe_ranges, ClassifiedVersion,
    get_upstream_versions, get_ranges_from_cve, get_version_ranges
)


def test_get_ranges_from_cve(maven_cve):
    """Test get_ranges_from_cve()."""
    affected, safe = get_ranges_from_cve(maven_cve, 'org.apache.tomcat:tomcat-catalina', 'java')
    assert len(affected) == 3
    affected_strings = [str(x) for x in affected]
    assert len(safe) == 4
    safe_strings = [str(x) for x in safe]

    expected_affected = ('<=7.0.90,7.0.23', '<=8.5.33,8.5.0', '<=9.0.11,9.0.0.M1')
    for item in expected_affected:
        assert item in affected_strings
        affected_strings.pop(affected_strings.index(item))
    assert not affected_strings

    expected_safe = ('>=9.0.12', '<=8.5.38,8.5.34', '<=8.0.53,7.0.91', '<=7.0.22,7.0.0')
    for item in expected_safe:
        assert item in safe_strings
        safe_strings.pop(safe_strings.index(item))
    assert not safe_strings


def test_get_ranges_from_cve_invalid(maven_cve):
    """Test get_ranges_from_cve() for invalid input."""
    with pytest.raises(ValueError):
        get_ranges_from_cve(maven_cve, None, 'java')
    with pytest.raises(ValueError):
        get_ranges_from_cve(maven_cve, 'a:b', None)
    with pytest.raises(ValueError):
        get_ranges_from_cve(None, 'a:b', 'java')
    with pytest.raises(ValueError):
        get_ranges_from_cve(maven_cve, 'a:b', 'maven')  # invalid ecosystem


def test_get_configuration_nodes(maven_cve):
    """Test get_configuration_nodes()."""
    nodes = get_configuration_nodes(maven_cve)
    assert len(nodes) == 2
    nodes = get_configuration_nodes(maven_cve, apps_only=False)
    assert len(nodes) == 4


def test_get_version_ranges(maven_cve):
    """Test get_version_ranges()."""
    nodes = get_configuration_nodes(maven_cve)
    ranges = get_version_ranges(nodes)
    assert len(ranges) == 2


def test_version_operator():
    """Test VersionOperator()."""
    assert VersionOperator('==') is VersionOperator.EQ
    assert VersionOperator('<=') is VersionOperator.LE
    assert VersionOperator('>=') is VersionOperator.GE

    with pytest.raises(ValueError):
        assert VersionOperator('!=')


def test_version_spec_le():
    """Test VersionSpec()."""
    spec_1 = VersionSpec.from_str('<=2.1.1')
    assert spec_1.contains('0.0.1')
    assert spec_1.contains('2.1.1')
    assert spec_1.contains('2')
    assert not spec_1.contains('2.1.2')
    assert not spec_1.contains('3.0.0')

    assert spec_1 == spec_1
    assert not spec_1 != spec_1
    assert not spec_1 < spec_1
    assert not spec_1 > spec_1
    assert spec_1 <= spec_1
    assert spec_1 >= spec_1


def test_version_spec_ge():
    """Test VersionSpec()."""
    spec_2 = VersionSpec.from_str('>=1.0.0')
    assert not spec_2.contains('0.0.1')
    assert spec_2.contains('1.0.0')
    assert spec_2.contains('2')


def test_version_spec_eq():
    """Test VersionSpec()."""
    spec_3 = VersionSpec.from_str('==1.0.0')
    assert spec_3.contains('1.0.0')
    assert spec_3.contains('1')
    assert not spec_3.contains('2')
    assert not spec_3.contains('0')

    assert spec_3 == spec_3
    assert not spec_3 != spec_3
    assert not spec_3 < spec_3
    assert not spec_3 > spec_3
    assert spec_3 <= spec_3
    assert spec_3 >= spec_3


def test_version_spec():
    """Test VersionSpec()."""
    spec_1 = VersionSpec.from_str('<=2.1.1')
    spec_2 = VersionSpec.from_str('>=1.0.0')
    spec_3 = VersionSpec.from_str('==1.0.0')

    assert not spec_1 == spec_2
    assert spec_1 != spec_2
    assert not spec_1 < spec_2
    assert spec_1 > spec_2
    assert not spec_1 <= spec_2
    assert spec_1 >= spec_2

    assert str(spec_1) == '<=2.1.1'
    assert str(spec_2) == '>=1.0.0'
    assert str(spec_3) == '==1.0.0'

    with pytest.raises(ValueError):
        assert VersionSpec.from_str('--')


def test_version_range():
    """Test VersionRange()."""
    ver_range = VersionRange('<=6.5.4', '>=5.0.0')
    assert ver_range.contains('6.0.0')
    assert not ver_range.contains('4.0.0')
    assert str(ver_range) == '<=6.5.4,5.0.0'

    ver_range = VersionRange('>=5.0.0', '<=6.5.4')
    assert ver_range.contains('6.0.0')
    assert not ver_range.contains('4.0.0')
    assert str(ver_range) == '<=6.5.4,5.0.0'

    ver_range = VersionRange('==1.0.0')
    assert ver_range.contains('1.0.0')
    assert not ver_range.contains('0.0.1')
    assert str(ver_range) == '==1.0.0'


def test_version_range_from_list():
    """Test VersionRange.from_list()."""
    ver_range = VersionRange.from_list(['1', '2', '3', '4'], is_right_closed=True)
    assert str(ver_range) == '<=4'

    ver_range = VersionRange.from_list(
        ['1', '2', '3', '4'], is_right_closed=True, is_left_closed=True
    )
    assert str(ver_range) == '<=4,1'

    ver_range = VersionRange.from_list(['1'], is_right_closed=True)
    assert str(ver_range) == '<=1'

    ver_range = VersionRange.from_list(['1'], is_right_closed=True, is_left_closed=True)
    assert str(ver_range) == '<=1,1'

    with pytest.raises(ValueError):
        VersionRange.from_list(['1', '2', '3', '4'])


def test_classify_versions():
    """Test classify_versions()."""
    versions = classify_versions(['2', '3', '4', '1'], [VersionRange('<=2.1')])

    expect_versions = ['1', '2', '3', '4']
    expect_affected = [True, True, False, False]
    for idx, v in enumerate(versions):
        assert v.version == expect_versions[idx]
        assert v.is_affected == expect_affected[idx]


def test_get_affected_ranges():
    """Test get_affected_ranges()."""
    ranges = get_affected_ranges(
        [
            ClassifiedVersion('1', False),
            ClassifiedVersion('2', True),
            ClassifiedVersion('3', False)
        ]
    )
    assert len(ranges) == 1
    assert str(ranges[0]) == '<=2,2'

    ranges = get_affected_ranges(
        [
            ClassifiedVersion('1', False),
            ClassifiedVersion('2', True),
            ClassifiedVersion('3', True)
        ]
    )
    assert len(ranges) == 1
    assert str(ranges[0]) == '<=3,2'

    ranges = get_affected_ranges(
        [
            ClassifiedVersion('1', False),
            ClassifiedVersion('2', False),
            ClassifiedVersion('3', False)
        ]
    )
    assert len(ranges) == 0

    ranges = get_affected_ranges(
        [
            ClassifiedVersion('1', True),
            ClassifiedVersion('2', False),
            ClassifiedVersion('3', True),
            ClassifiedVersion('4', True),
            ClassifiedVersion('5', False)
        ]
    )
    assert len(ranges) == 2
    assert str(ranges[0]) == '<=1'
    assert str(ranges[1]) == '<=4,3'


def test_get_safe_ranges():
    """Test get_safe_ranges()."""
    ranges = get_safe_ranges(
        [
            ClassifiedVersion('1', True),
            ClassifiedVersion('2', True),
            ClassifiedVersion('3', False)
        ]
    )
    assert len(ranges) == 1
    assert str(ranges[0]) == '>=3'

    ranges = get_safe_ranges(
        [
            ClassifiedVersion('1', True),
            ClassifiedVersion('2', False),
            ClassifiedVersion('3', False)
        ]
    )
    assert len(ranges) == 1
    assert str(ranges[0]) == '>=2'

    ranges = get_safe_ranges(
        [
            ClassifiedVersion('1', True),
            ClassifiedVersion('2', False),
            ClassifiedVersion('3', True)
        ]
    )
    assert len(ranges) == 1
    assert str(ranges[0]) == '<=2,2'

    ranges = get_safe_ranges(
        [
            ClassifiedVersion('1', True),
            ClassifiedVersion('2', False),
            ClassifiedVersion('3', False),
            ClassifiedVersion('4', True)
        ]
    )
    assert len(ranges) == 1
    assert str(ranges[0]) == '<=3,2'

    ranges = get_safe_ranges(
        [
            ClassifiedVersion('1', False),
            ClassifiedVersion('2', True),
            ClassifiedVersion('3', True)
        ]
    )
    assert len(ranges) == 1
    assert str(ranges[0]) == '<=1,1'

    ranges = get_safe_ranges(
        [
            ClassifiedVersion('1', True),
            ClassifiedVersion('2', True),
            ClassifiedVersion('3', True)
        ]
    )
    assert len(ranges) == 0


def test_get_upstream_versions(mocker):
    """Test get_upstream_versions()."""
    mocker.patch(
        'cvejob.version_utils.get_versions_for_maven_package', lambda x: ['1.2', '1.3', '1.4']
    )
    mocker.patch(
        'cvejob.version_utils.get_versions_for_pypi_package',
        lambda x: ['1', '2', '3']
    )
    mocker.patch(
        'cvejob.version_utils.get_versions_for_npm_package',
        lambda x: ['1.0.0', '0.0.9', '0.0.8']
    )

    assert get_upstream_versions('gid:aid', 'java') == ['1.2', '1.3', '1.4']
    assert get_upstream_versions('pypi_pkg', 'python') == ['1', '2', '3']
    assert get_upstream_versions('npm_pkg', 'javascript') == ['1.0.0', '0.0.9', '0.0.8']

    with pytest.raises(ValueError):
        get_upstream_versions('abc', 'xyz')

    with pytest.raises(ValueError):
        get_upstream_versions(None, 'java')

    with pytest.raises(ValueError):
        get_upstream_versions('gid:aid', None)
