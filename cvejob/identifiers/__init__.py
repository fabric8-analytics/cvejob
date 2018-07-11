"""This package contains identifiers.

Identifiers are responsible for identifying package name candidates.
"""

from cvejob.config import Config
from cvejob.identifiers.basic import NaivePackageNameIdentifier
from cvejob.identifiers.nvdtoolkit import NvdToolkitPackageNameIdentifier


def get_identifier(cve):
    """Get identifier object."""
    if not Config.use_nvdtoolkit:
        cls = NaivePackageNameIdentifier
    else:
        cls = NvdToolkitPackageNameIdentifier
    return cls(cve)
