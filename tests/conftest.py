"""Configuration for tests."""

import pytest
import json
from nvdlib.model import CVE

from cvejob.config import DefaultConfig


@pytest.fixture
def javascript_cve():
    """JavaScript CVE fixture."""
    with open('tests/data/javascript-nvdcve.json') as f:
        nvd_json = json.load(f)
        return CVE.from_dict(nvd_json['CVE_Items'][0])


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
