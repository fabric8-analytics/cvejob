"""This package contains identifiers.

Identifiers are responsible for identifying package name candidates.
"""

from cvejob.identifiers.naive import NaivePackageNameIdentifier
# from cvejob.identifiers.nvdtoolkit import NvdToolkitPackageNameIdentifier


def get_identifier_cls(use_nvdtoolkit=False):
    """Get identifier class."""
    if not use_nvdtoolkit:
        cls = NaivePackageNameIdentifier
    else:
        raise NotImplementedError(
            "Identifier 'nvd-toolkit' is currently disabled due to nvdlib version incompatibility."
            " See nvd-toolkit migration status at:"
            " https://github.com/fabric8-analytics/fabric8-analytics-nvd-toolkit"
        )
        # cls = NvdToolkitPackageNameIdentifier
    return cls
