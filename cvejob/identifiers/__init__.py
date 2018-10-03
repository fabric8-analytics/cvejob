"""This package contains identifiers.

Identifiers are responsible for identifying package name candidates.
"""

from cvejob.config import Config
from cvejob.identifiers.basic import NaivePackageNameIdentifier
# from cvejob.identifiers.nvdtoolkit import NvdToolkitPackageNameIdentifier


def get_identifier(cve):
    """Get identifier object."""
    if not Config.use_nvdtoolkit:
        cls = NaivePackageNameIdentifier
    else:
        raise NotImplementedError(
            "Identifier 'nvd-toolkit' is currently disabled due to nvdlib version incompatibility."
            " See nvd-toolkit migration status at:"
            " https://github.com/fabric8-analytics/fabric8-analytics-nvd-toolkit"
        )
        # cls = NvdToolkitPackageNameIdentifier
    return cls(cve)
