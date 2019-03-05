"""Tests for cvejob.versions.version_identifier module."""

from cvejob.versions import NVDVersions


def test_nvd_versions(python_cve):
    """Test NVDVersions().run()."""
    affected, safe = NVDVersions(python_cve, 'numpy', 'python').run()
    assert affected
    assert len(affected) == 1
    assert str(affected[0]) == '<=1.16.0'

    assert safe
    assert len(safe) == 1
    assert str(safe[0]) == '>=1.16.1'
