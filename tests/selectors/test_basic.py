"""Tests for cvejob.selectors.basic module."""

from cvejob.selectors import VersionSelector
from cvejob.cpe2pkg import PackageNameCandidate
from decimal import Decimal


def test_basic_selector(maven_vertx_cve):
    """Test VersionSelector().pick_winner()."""
    candidates = [
        PackageNameCandidate('io.vertx:testtools', Decimal('10.0')),
        PackageNameCandidate('io.vertx:vertx-core', Decimal('5.0'))
    ]
    selector = VersionSelector(maven_vertx_cve, candidates, 'java')
    winner = selector.pick_winner()
    assert winner
    assert winner.package == 'io.vertx:vertx-core'


def test_basic_selector_none_versions(unsupported_cve_none_versions):
    """Test VersionSelector().pick_winner() with "None" versions."""
    candidates = [
        PackageNameCandidate('io.vertx:testtools', Decimal('10.0')),
    ]
    selector = VersionSelector(unsupported_cve_none_versions, candidates, 'java')
    winner = selector.pick_winner()  # don't throw TypeError here
    assert not winner
