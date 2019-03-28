"""Test for the config.py."""

# import pytest

from cvejob.config import DefaultConfig, RuntimeConfig


def test_default_config_constructor():
    """Basic test for the class DefaultConfig."""
    config = DefaultConfig()
    assert config is not None


def test_default_config_attributes():
    """Basic test for the class DefaultConfig."""
    config = DefaultConfig()

    # basic configuration check
    attributes = ("ecosystem", "cve_age", "feed_dir", "feed_names", "date_range", "cve_id",
                  "package_name", "cpe2pkg_path", "pkgfile_dir", "use_nvdtoolkit",
                  "nvdtoolkit_export_dir")
    for attribute in attributes:
        assert hasattr(config, attribute)


def test_runtime_config():
    """Basic test for the class RuntimeConfig."""
    config = RuntimeConfig()
    assert config is not None
