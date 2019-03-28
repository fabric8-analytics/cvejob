"""Test for the config.py."""

# import pytest

from cvejob.config import DefaultConfig, RuntimeConfig


def test_default_config():
    """Basic test for the class DefaultConfig."""
    config = DefaultConfig()
    assert config is not None


def test_runtime_config():
    """Basic test for the class RuntimeConfig."""
    config = RuntimeConfig()
    assert config is not None
