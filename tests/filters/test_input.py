"""Test cvejob.filters.input module."""

import pytest


from cvejob.filters.input import (
    validate_cve,
    NotOlderThanCheck,
    NotUnsupportedFileExtensionCheck,
    NotUnderAnalysisCheck,
    IsSupportedGitHubLanguageCheck,
    AffectsApplicationCheck,
    IsCherryPickedCveCheck,
    NotUnexpectedSiteInReferencesCheck
)


def test_not_older_than_check(config, javascript_cve, mocker):
    """Test NotOlderThanCheck()."""
    mocker.patch('cvejob.filters.input.Config', config(cve_age=10000))

    check = NotOlderThanCheck(javascript_cve)
    assert check.check()


def test_not_unsupported_file_extension_check(javascript_cve):
    """Test NotUnsupportedFileExtensionCheck()."""
    check = NotUnsupportedFileExtensionCheck(javascript_cve)
    assert check.check()


def test_not_under_analysis_check(javascript_cve):
    """Test NotUnderAnalysisCheck()."""
    check = NotUnderAnalysisCheck(javascript_cve)
    assert check.check()


def test_is_supported_github_language_check(config, javascript_cve, mocker):
    """Test IsSupportedGitHubLanguageCheck()."""
    mocker.patch('cvejob.filters.input.Config', config(ecosystem='javascript'))

    check = IsSupportedGitHubLanguageCheck(javascript_cve)
    assert check.check()


@pytest.mark.parametrize('owner,repo,expected', [
    ('owner', 'NPM-Vuln-PoC', True),
    ('NPM-Vuln-PoC', 'repo', True),
    ('BlockChainsSecurity', 'Reports', True),
    ('owner', 'VulnerabilitiesReport', True),
    ('fabric8-analytics', 'CveDB', True),
    ('fabric8-analytics', 'fabric8-analytics-worker', False)
])
def test_is_security_project(javascript_cve, owner, repo, expected):
    """Test IsSupportedGitHubLanguageCheck().is_security_project()."""
    check = IsSupportedGitHubLanguageCheck(javascript_cve)
    assert check.is_security_project(owner, repo) == expected


def test_affects_application_check(javascript_cve):
    """Test AffectsApplicationCheck()."""
    check = AffectsApplicationCheck(javascript_cve)
    assert check.check()


def test_is_cherrypicked_cve_check(config, javascript_cve, mocker):
    """Test IsCherryPickedCveCheck()."""
    mocker.patch('cvejob.filters.input.Config', config(cve_id='CVE-2018-3757'))

    check = IsCherryPickedCveCheck(javascript_cve)
    assert check.check()


def test_not_unexpected_site_in_references_check(config, javascript_cve, mocker):
    """Test NotUnexpectedSiteInReferences()."""
    mocker.patch('cvejob.filters.input.Config', config(ecosystem='javascript'))

    check = NotUnexpectedSiteInReferencesCheck(javascript_cve)
    assert check.check()


def test_not_unexpected_site_in_references_check_fail(config, javascript_cve, mocker):
    """Test NotUnexpectedSiteInReferences() fail."""
    mocker.patch('cvejob.filters.input.Config', config(ecosystem='python'))

    check = NotUnexpectedSiteInReferencesCheck(javascript_cve)
    assert not check.check()


def test_cve_id_cve_age(config, javascript_cve, mocker):
    """Test scenario when both `cve_id` and `cve_age` options are set."""
    # cve_age='1': CVE is older, but the check should be excluded automatically
    mocker.patch('cvejob.filters.input.Config', config(cve_id='CVE-2018-3757', cve_age='1'))

    assert validate_cve(
        javascript_cve,
        exclude_checks=[
            NotUnsupportedFileExtensionCheck,
            IsSupportedGitHubLanguageCheck,
            NotUnexpectedSiteInReferencesCheck
        ]
    )


def test_validate_cve_exclude(config, javascript_cve, mocker):
    """Test excluding some checks."""
    # 'cve_id': 'CVE-2018-nope'  # doesn't exist, but we exclude the check
    mocker.patch('cvejob.filters.input.Config', config(cve_id='CVE-2018-nope'))

    assert validate_cve(
        javascript_cve,
        exclude_checks=[
            IsCherryPickedCveCheck,
            NotUnsupportedFileExtensionCheck,
            IsSupportedGitHubLanguageCheck,
            NotUnexpectedSiteInReferencesCheck
        ]
    )
