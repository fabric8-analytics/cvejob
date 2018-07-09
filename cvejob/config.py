"""Global configuration for the project."""

import os


class Config(object):
    """Configuration holder."""

    _config = {
        'ecosystem': os.environ.get('CVEJOB_ECOSYSTEM') or 'python',
        'cve_age': int(os.environ.get('CVEJOB_CVE_AGE', 0)),
        'feed_path': os.environ.get('CVEJOB_FEED_PATH') or 'nvdcve.json',
        'cve_id': os.environ.get('CVEJOB_CVE_ID') or None,
        'cpe2pkg_path': os.environ.get('CVEJOB_CPE2PKG_PATH') or 'cpe2pkg.jar',
        'pkgfile_dir': os.environ.get('CVEJOB_PKGFILE_DIR') or 'data/',
        'use_nvdtoolkit': os.environ.get(
            'CVEJOB_USE_NVD_TOOLKIT', 'false').lower() in ('true', '1', 'yes'),
        'nvdtoolkit_export_dir': os.environ.get('CVEJOB_NVD_TOOLKIT_EXPORT_DIR') or 'export/'
    }

    @staticmethod
    def get(name):
        """Get config value by name."""
        return Config._config.get(name)

    @staticmethod
    def set(name, value):
        """Set config value."""
        if name in Config._config:
            Config._config[name] = value
        else:
            raise ValueError('Invalid configuration option: {n}'.format(n=name))
