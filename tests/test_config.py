"""Test for the config.py."""

# import pytest

from cvejob.config import DefaultConfig, RuntimeConfig


def test_default_config_constructor():
    """Basic test for the class DefaultConfig."""
    config = DefaultConfig()
    assert config is not None


def test_default_config_attributes():
    """Check the attributes existence for a class DefaultConfig."""
    config = DefaultConfig()

    # basic configuration check
    attributes = ("ecosystem", "cve_age", "feed_dir", "feed_names", "date_range", "cve_id",
                  "package_name", "cpe2pkg_path", "pkgfile_dir", "use_nvdtoolkit",
                  "nvdtoolkit_export_dir")
    for attribute in attributes:
        assert hasattr(config, attribute)


def test_default_config_attribute_values_nil():
    """Check the attributes that needs to be set to nil (None)."""
    config = DefaultConfig()

    # the following attributes needs to be set to nil
    assert config.feed_names is None
    assert config.date_range is None
    assert config.cve_id is None
    assert config.package_name is None
    assert config.feed_names is None


def test_default_config_attribute_values_not_nil():
    """Check the attributes that needs not to be set to nil (None)."""
    config = DefaultConfig()

    # the following attributes need not be set to nil
    assert config.ecosystem is not None
    assert config.cve_age is not None
    assert config.feed_dir is not None
    assert config.cpe2pkg_path is not None
    assert config.pkgfile_dir is not None
    assert config.use_nvdtoolkit is not None
    assert config.nvdtoolkit_export_dir is not None


def test_runtime_config():
    """Basic test for the class RuntimeConfig."""
    config = RuntimeConfig()
    assert config is not None
