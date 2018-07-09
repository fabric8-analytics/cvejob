"""Configuration for tests."""

import pytest
import json
from nvdlib.model import CVE


@pytest.fixture
def javascript_cve():
    """JavaScript CVE fixture."""
    with open('tests/data/javascript-nvdcve.json') as f:
        nvd_json = json.load(f)
        return CVE.from_dict(nvd_json['CVE_Items'][0])
