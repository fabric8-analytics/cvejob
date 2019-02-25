"""Configuration for tests."""

import pytest
import json
from nvdlib.model import Document

from cvejob.config import DefaultConfig


@pytest.fixture
def javascript_cve():
    """JavaScript CVE fixture."""
    with open('tests/data/javascript-nvdcve.json') as f:
        data, = json.load(f)['CVE_Items']
        return Document.from_data(data)


@pytest.fixture
def maven_cve():
    """Maven CVE fixture."""
    with open('tests/data/maven-nvdcve.json') as f:
        data, = json.load(f)['CVE_Items']
        return Document.from_data(data)


@pytest.fixture
def rejected_cve():
    """Rejected CVE fixture."""
    with open('tests/data/rejected-nvdcve.json') as f:
        data, = json.load(f)['CVE_Items']
        return Document.from_data(data)


@pytest.fixture
def unsupported_cve():
    """Unsupported ecosystem CVE fixture."""
    with open('tests/data/unsupported-nvdcve.json') as f:
        data, = json.load(f)['CVE_Items']
        return Document.from_data(data)


@pytest.fixture
def config():
    """Config for testing based on default config."""
    def create_test_config(**kwargs):
        config_obj = DefaultConfig()

        for attr, value in kwargs.items():
            if hasattr(config_obj, attr):
                setattr(config_obj, attr, value)
            else:
                raise ValueError('Invalid configuration option: {a}'.format(a=attr))

        return config_obj
    return create_test_config
