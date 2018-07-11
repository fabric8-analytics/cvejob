"""Test cvejob.filters.input module."""

from cvejob.filters.input import (
    NotOlderThanCheck,
    NotUnsupportedFileExtensionCheck,
    NotUnderAnalysisCheck,
    IsSupportedGitHubLanguageCheck,
    AffectsApplicationCheck,
    IsCherryPickedCveCheck,
    NotUnexpectedSiteInReferences
)


def test_not_older_than_check(javascript_cve, mocker):
    """Test NotOlderThanCheck()."""
    config_get = mocker.patch('cvejob.filters.input.Config.get')
    config_get.return_value = 100000

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


def test_is_supported_github_language_check(javascript_cve, mocker):
    """Test IsSupportedGitHubLanguageCheck()."""
    config_get = mocker.patch('cvejob.filters.input.Config.get')
    config_get.return_value = 'javascript'

    check = IsSupportedGitHubLanguageCheck(javascript_cve)
    assert check.check()


def test_affects_application_check(javascript_cve):
    """Test AffectsApplicationCheck()."""
    check = AffectsApplicationCheck(javascript_cve)
    assert check.check()


def test_is_cherrypicked_cve_check(javascript_cve, mocker):
    """Test IsCherryPickedCveCheck()."""
    config_get = mocker.patch('cvejob.filters.input.Config.get')
    config_get.return_value = 'CVE-2018-3757'

    check = IsCherryPickedCveCheck(javascript_cve)
    assert check.check()


def test_not_unexpected_site_in_references_check(javascript_cve, mocker):
    """Test NotUnexpectedSiteInReferences()."""
    config_get = mocker.patch('cvejob.filters.input.Config.get')
    config_get.return_value = 'javascript'

    check = NotUnexpectedSiteInReferences(javascript_cve)
    assert check.check()


def test_not_unexpected_site_in_references_check_fail(javascript_cve, mocker):
    """Test NotUnexpectedSiteInReferences() fail."""
    config_get = mocker.patch('cvejob.filters.input.Config.get')
    config_get.return_value = 'python'

    check = NotUnexpectedSiteInReferences(javascript_cve)
    assert not check.check()
