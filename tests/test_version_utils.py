"""Tests for cvejob.version_utils module."""

import pytest
from cvejob.version_utils import (
    get_configuration_nodes, VersionOperator, VersionSpec, VersionRange,
    classify_versions, get_affected_ranges, get_safe_ranges, ClassifiedVersion,
    get_upstream_versions, get_ranges_from_cve, get_version_ranges
)


def test_get_ranges_from_cve(mocker, maven_cve):
    """Test get_ranges_from_cve()."""
    # Mock response from Maven Central
    mocker.patch(
        'cvejob.version_utils.get_versions_for_maven_package',
        lambda x: [
            '7.0.0', '7.0.2', '7.0.4', '7.0.5', '7.0.6', '7.0.8', '7.0.11', '7.0.12', '7.0.14',
            '7.0.16', '7.0.19', '7.0.20', '7.0.21', '7.0.22', '7.0.23', '7.0.25', '7.0.26',
            '7.0.27', '7.0.28', '7.0.29', '7.0.30', '7.0.32', '7.0.33', '7.0.34', '7.0.35',
            '7.0.37', '7.0.39', '7.0.40', '7.0.41', '7.0.42', '7.0.47', '7.0.50', '7.0.52',
            '7.0.53', '7.0.54', '7.0.55', '7.0.56', '7.0.57', '7.0.59', '7.0.61', '7.0.62',
            '7.0.63', '7.0.64', '7.0.65', '7.0.67', '7.0.68', '7.0.69', '7.0.70', '7.0.72',
            '7.0.73', '7.0.75', '7.0.76', '7.0.77', '7.0.78', '7.0.79', '7.0.81', '7.0.82',
            '7.0.84', '7.0.85', '7.0.86', '7.0.88', '7.0.90', '7.0.91', '7.0.92', '7.0.93',
            '8.0.0-RC1', '8.0.0-RC3', '8.0.0-RC5', '8.0.0-RC10', '8.0.1', '8.0.3', '8.0.5',
            '8.0.8', '8.0.9', '8.0.11', '8.0.12', '8.0.14', '8.0.15', '8.0.17', '8.0.18',
            '8.0.20', '8.0.21', '8.0.22', '8.0.23', '8.0.24', '8.0.26', '8.0.27', '8.0.28',
            '8.0.29', '8.0.30', '8.0.32', '8.0.33', '8.0.35', '8.0.36', '8.0.37', '8.0.38',
            '8.0.39', '8.0.41', '8.0.42', '8.0.43', '8.0.44', '8.0.45', '8.0.46', '8.0.47',
            '8.0.48', '8.0.49', '8.0.50', '8.0.51', '8.0.52', '8.0.53', '8.5.0', '8.5.2',
            '8.5.3', '8.5.4', '8.5.5', '8.5.6', '8.5.8', '8.5.9', '8.5.11', '8.5.12',
            '8.5.13', '8.5.14', '8.5.15', '8.5.16', '8.5.19', '8.5.20', '8.5.21', '8.5.23',
            '8.5.24', '8.5.27', '8.5.28', '8.5.29', '8.5.30', '8.5.31', '8.5.32', '8.5.33',
            '8.5.34', '8.5.35', '8.5.37', '8.5.38', '9.0.0.M1', '9.0.0.M3',
            '9.0.0.M4', '9.0.0.M6', '9.0.0.M8', '9.0.0.M9', '9.0.0.M10', '9.0.0.M11',
            '9.0.0.M13', '9.0.0.M15', '9.0.0.M17', '9.0.0.M18', '9.0.0.M19', '9.0.0.M20',
            '9.0.0.M21', '9.0.0.M22', '9.0.0.M25', '9.0.0.M26', '9.0.0.M27', '9.0.1',
            '9.0.2', '9.0.4', '9.0.5', '9.0.6', '9.0.7', '9.0.8', '9.0.10', '9.0.11',
            '9.0.12', '9.0.13', '9.0.14', '9.0.16', '9.0.17'
        ]
    )
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
    assert VersionOperator('<') is VersionOperator.LT
    assert VersionOperator('>') is VersionOperator.GT

    # test with invalid input
    with pytest.raises(ValueError):
        assert VersionOperator('!=')


def test_version_spec_le():
    """Test VersionSpec() for less-equal operator."""
    spec_1 = VersionSpec.from_str('<=2.1.1')
    assert spec_1.contains('0.0.1')
    assert spec_1.contains('2.1.1')
    assert spec_1.contains('2')
    assert not spec_1.contains('2.1.2')
    assert not spec_1.contains('3.0.0')


def test_version_spec_ge():
    """Test VersionSpec() for greater-equal operator."""
    spec_2 = VersionSpec.from_str('>=1.0.0')
    assert not spec_2.contains('0.0.1')
    assert spec_2.contains('1.0.0')
    assert spec_2.contains('1.0.1')
    assert spec_2.contains('2')


def test_version_spec_eq():
    """Test VersionSpec() for == operator."""
    spec_3 = VersionSpec.from_str('==1.0.0')
    assert spec_3.contains('1.0.0')
    assert spec_3.contains('1')
    assert not spec_3.contains('2')
    assert not spec_3.contains('0')


def test_version_spec_lt():
    """Test VersionSpec() for less-than operator."""
    spec_1 = VersionSpec.from_str('<2.1.1')
    assert spec_1.contains('0.0.1')
    assert spec_1.contains('2.1.0')
    assert spec_1.contains('2')
    assert not spec_1.contains('2.1.2')
    assert not spec_1.contains('2.1.1')
    assert not spec_1.contains('3.0.0')


def test_version_spec_gt():
    """Test VersionSpec() for greater-than operator."""
    spec_1 = VersionSpec.from_str('>2.1.1')
    assert not spec_1.contains('0.0.1')
    assert not spec_1.contains('2.1.1')
    assert not spec_1.contains('2')
    assert spec_1.contains('2.1.2')
    assert spec_1.contains('3.0.0')
    assert spec_1.contains('3')


def test_version_spec_cmp_ge_gt():
    """Test VersionSpec(), greater and greater-than comparison."""
    assert VersionSpec.from_str('<=1') > VersionSpec.from_str('>=2')
    assert VersionSpec.from_str('<=1') > VersionSpec.from_str('>2')
    assert VersionSpec.from_str('<=1') >= VersionSpec.from_str('>=2')
    assert VersionSpec.from_str('<=1') >= VersionSpec.from_str('>2')

    assert VersionSpec.from_str('<1') > VersionSpec.from_str('>=2')
    assert VersionSpec.from_str('<1') > VersionSpec.from_str('>2')
    assert VersionSpec.from_str('<1') >= VersionSpec.from_str('>=2')
    assert VersionSpec.from_str('<1') >= VersionSpec.from_str('>2')


def test_version_spec_cmp_le_lt():
    """Test VersionSpec(), less and less-than comparison."""
    assert VersionSpec.from_str('>=1') < VersionSpec.from_str('<=2')
    assert VersionSpec.from_str('>=1') < VersionSpec.from_str('<2')
    assert VersionSpec.from_str('>=1') <= VersionSpec.from_str('<=2')
    assert VersionSpec.from_str('>=1') <= VersionSpec.from_str('<2')

    assert VersionSpec.from_str('>1') < VersionSpec.from_str('<=2')
    assert VersionSpec.from_str('>1') < VersionSpec.from_str('<2')
    assert VersionSpec.from_str('>1') <= VersionSpec.from_str('<=2')
    assert VersionSpec.from_str('>1') <= VersionSpec.from_str('<2')


def test_version_spec_cmp_misc():
    """Test VersionSpec()."""
    assert VersionSpec.from_str('==1') == VersionSpec.from_str('==2')
    assert VersionSpec.from_str('<=1') == VersionSpec.from_str('<=2')
    assert VersionSpec.from_str('<1') == VersionSpec.from_str('<2')
    assert VersionSpec.from_str('>=1') == VersionSpec.from_str('>=2')
    assert VersionSpec.from_str('>1') == VersionSpec.from_str('>2')

    assert not VersionSpec.from_str('==1') < VersionSpec.from_str('<=2')
    assert not VersionSpec.from_str('==1') < VersionSpec.from_str('>=2')
    assert not VersionSpec.from_str('==1') < VersionSpec.from_str('<2')
    assert not VersionSpec.from_str('==1') < VersionSpec.from_str('>2')


def test_version_spec_from_str():
    """Test VersionSpec.from_str()."""
    spec_le = VersionSpec.from_str('<=2.1.1')
    spec_ge = VersionSpec.from_str('>=1.0.0')
    spec_eq = VersionSpec.from_str('==1.0.0')
    spec_lt = VersionSpec.from_str('<3.0.0')
    spec_gt = VersionSpec.from_str('>3.0.0')

    assert str(spec_le) == '<=2.1.1'
    assert str(spec_ge) == '>=1.0.0'
    assert str(spec_eq) == '==1.0.0'
    assert str(spec_lt) == '<3.0.0'
    assert str(spec_gt) == '>3.0.0'

    # test with invalid input
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

    # test with no affected versions
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

    # test with no safe versions
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

    # test with invalid input
    with pytest.raises(ValueError):
        get_upstream_versions('abc', 'xyz')

    with pytest.raises(ValueError):
        get_upstream_versions(None, 'java')

    with pytest.raises(ValueError):
        get_upstream_versions('gid:aid', None)
