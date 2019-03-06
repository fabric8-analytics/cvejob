"""Tests for cvejob.cpe2pkg module."""

from cvejob.cpe2pkg import PackageNameCandidate, get_pkgfile_path, build_cpe2pkg_query, run_cpe2pkg
from decimal import Decimal

import pytest
from pathlib import Path


def test_package_name_candidate():
    """Test PackageNameCandidate()."""
    c1 = PackageNameCandidate.from_cpe2pkg_output('10.0 python:package-a', 'python')

    assert c1.package == 'package-a'
    assert c1.score == Decimal('10.0')
    assert str(c1) == 'PackageNameCandidate(package-a, 10.0)'
    assert c1 == c1

    c2 = PackageNameCandidate.from_cpe2pkg_output('9.0 python:package-b', 'python')
    assert c1 > c2
    assert c2 < c1
    assert c1 != c2

    c3 = PackageNameCandidate.from_cpe2pkg_output('9.0 gid:package-c', 'java')
    assert c3.package == 'gid:package-c'


def test_package_name_candidate_bad():
    """Test PackageNameCandidate() with invalid input."""
    with pytest.raises(ValueError):
        PackageNameCandidate(None, Decimal('1.0'))
    with pytest.raises(ValueError):
        PackageNameCandidate('', Decimal('1.0'))
    with pytest.raises(ValueError):
        PackageNameCandidate('package-a', None)

    # extra element ("UI") in the cpe2pkg output line
    candidate = PackageNameCandidate.from_cpe2pkg_output(
        '1.0268737 javascript:JQuery UI', 'javascript'
    )
    assert candidate.package == 'JQuery'


@pytest.mark.parametrize('pkgfile_dir,ecosystem,expected', [
    ('/pkgfile/dir/', 'java', '/pkgfile/dir/java-packages'),
    ('/pkgfile/dir', 'python', '/pkgfile/dir/python-packages'),
    ('/pkgfile/dir/', 'xyz', '/pkgfile/dir/xyz-packages'),
])
def test_get_pkgfile_path(pkgfile_dir, ecosystem, expected):
    """Test get_pkgfile_path()."""
    assert get_pkgfile_path(pkgfile_dir, ecosystem) == expected


@pytest.mark.parametrize('vendor,product,query', [
    (
        ['apache', 'foundation'], ['tomcat', 'server'],
        'vendor:( apache foundation ) AND product:( tomcat server )'
    ),
    (
        ['apache', 'foundation'], ['apache::tomcat', 'server'],
        'vendor:( apache foundation ) AND product:( apache  tomcat server )'
    )
])
def test_build_cpe2pkg_query(vendor, product, query):
    """Test build_cpe2pkg_query()."""
    assert build_cpe2pkg_query(vendor, product) == query


def test_run_cpe2pkg(mocker):
    """Test run_cpe2pkg().

    We are not really running the tool here, just mocking it.
    """
    mock_output = """
1.1375153 io.vertx:vertx-core
0.13637602 io.vertx:vertx-auth
0.13637602 io.vertx:vertx-codegen
0.13637602 io.vertx:vertx-codetrans
"""
    mock = mocker.patch('cvejob.cpe2pkg.subprocess.check_output')
    mock.return_value = mock_output
    pkgfile_path = Path(__file__).parent / Path('data/java-pkgfile')
    results = run_cpe2pkg(
        'vendor:( vertx ) AND product:( vertx io core framework )', pkgfile_path
    )
    assert len(results) == 4
    assert results[0] == '1.1375153 io.vertx:vertx-core'
    assert all(results)
