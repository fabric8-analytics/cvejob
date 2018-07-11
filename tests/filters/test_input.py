"""Test cvejob.filters.input module."""

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

    check = NotUnexpectedSiteInReferencesCheck(javascript_cve)
    assert check.check()


def test_not_unexpected_site_in_references_check_fail(javascript_cve, mocker):
    """Test NotUnexpectedSiteInReferences() fail."""
    config_get = mocker.patch('cvejob.filters.input.Config.get')
    config_get.return_value = 'python'

    check = NotUnexpectedSiteInReferencesCheck(javascript_cve)
    assert not check.check()


def test_cve_id_cve_age(javascript_cve, mocker):
    """Test scenario when both `cve_id` and `cve_age` options are set."""
    def config_get(key):
        config = {
            'cve_id': 'CVE-2018-3757',
            'cve_age': 1  # CVE is older, but the check should be excluded automatically
        }
        return config.get(key)

    config_get_mock = mocker.patch('cvejob.filters.input.Config.get')
    config_get_mock.side_effect = config_get

    assert validate_cve(
        javascript_cve,
        exclude_checks=[
            NotUnsupportedFileExtensionCheck,
            IsSupportedGitHubLanguageCheck,
            NotUnexpectedSiteInReferencesCheck
        ]
    )


def test_validate_cve_exclude(javascript_cve, mocker):
    """Test excluding some checks."""
    def config_get(key):
        config = {
            'cve_id': 'CVE-2018-nope'  # doesn't exist, but we exclude the check
        }
        return config.get(key)

    config_get_mock = mocker.patch('cvejob.filters.input.Config.get')
    config_get_mock.side_effect = config_get

    assert validate_cve(
        javascript_cve,
        exclude_checks=[
            IsCherryPickedCveCheck,
            NotUnsupportedFileExtensionCheck,
            IsSupportedGitHubLanguageCheck,
            NotUnexpectedSiteInReferencesCheck
        ]
    )
