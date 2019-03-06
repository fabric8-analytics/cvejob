"""Configuration for tests."""

import pytest
import json
from pathlib import Path
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
def python_cve():
    """Maven CVE fixture."""
    with open('tests/data/python-nvdcve.json') as f:
        data, = json.load(f)['CVE_Items']
        return Document.from_data(data)


@pytest.fixture
def maven_vertx_cve():
    """Maven Vert.x CVE fixture."""
    with open('tests/data/maven-vertx-nvdcve.json') as f:
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
def unsupported_cve_none_versions():
    """Unsupported ecosystem CVE fixture.

    Some of the CVE versions in this CVE are "None".
    """
    with open('tests/data/unsupported-nvdcve-2.json') as f:
        data, = json.load(f)['CVE_Items']
        return Document.from_data(data)


@pytest.fixture
def cpe2pkg_tool():
    """Unsupported ecosystem CVE fixture."""
    bin = Path(__file__).parent.parent / Path('tools/bin/cpe2pkg.jar')
    if bin.exists():
        return str(bin)
    else:
        raise RuntimeError('`cpe2pkg.jar` is not available, please run `make build-cpe2pkg once.`')


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
