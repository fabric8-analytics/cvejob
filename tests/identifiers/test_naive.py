"""Tests for cvejob.identifiers.naive module."""

import pytest
from pathlib import Path
from cvejob.identifiers import NaivePackageNameIdentifier, get_identifier_cls


def test_naive_basic(maven_vertx_cve, cpe2pkg_tool):
    """Basic test for NaivePackageNameIdentifier().identify().

    This is a "package name guess" test with a limited number of potential candidates.
    We expect to always find the correct package name in the result set.
    """
    pkgfile_path = Path(__file__).parent.parent / Path('data/java-pkgfile')
    identifier = NaivePackageNameIdentifier(
        maven_vertx_cve, 'java', pkgfile_path, cpe2pkg_tool
    )
    candidates = identifier.identify()
    assert len(candidates) == 10
    assert 'io.vertx:vertx-core' in [x.package for x in candidates]


def test_get_identifier_cls():
    """Test get_identifier_cls()."""
    cls = get_identifier_cls()
    assert cls == NaivePackageNameIdentifier

    with pytest.raises(NotImplementedError):
        get_identifier_cls(use_nvdtoolkit=True)
