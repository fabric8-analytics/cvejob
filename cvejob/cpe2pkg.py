"""Wrapper around cpe2pkg tool and various helper structures/functions."""

from cvejob.config import Config

from decimal import Decimal
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger('cvejob')


class PackageNameCandidate(object):
    """Package name candidate, with associated confidence score."""

    def __init__(self, package, score):
        """Instantiate PackageNameCandidate().

        :param package: str, package name
        :param score: decimal.Decimal, confidence score
        """
        if not package or not isinstance(package, str):
            raise ValueError('"package" must be a non-empty string')
        if not isinstance(score, Decimal):
            raise ValueError('"score" must be a Decimal')

        self.package = package
        self.score = score

    def __repr__(self):
        return 'PackageNameCandidate({p}, {s})'.format(p=self.package, s=self.score)

    def __eq__(self, other):
        return self.score == other.score

    def __lt__(self, other):
        return self.score < other.score

    def __le__(self, other):
        return self.score <= other.score

    @classmethod
    def from_cpe2pkg_output(cls, output_line, ecosystem):
        """Build PackageNameCandidate from the output of cpe2pkg.

        :param output_line: str, single line of the cpe2pkg output
        :param ecosystem: str, ecosystem name
        """
        score_str, package, *_ = output_line.split()
        score = Decimal(score_str)

        # ecosystems other than "java" don't have group IDs
        if ecosystem != 'java':
            package = package[len(ecosystem) + 1:]  # strip "ecosystem:"

        return cls(package, score)


def get_pkgfile_path(pkgfile_dir, ecosystem):
    """Get path to pkgfile for given ecosystem."""
    return str(Path(pkgfile_dir) / Path('{e}-packages'.format(e=ecosystem)))


def run_cpe2pkg(query_str, pkgfile_path, cpe2pkg_path=Config.cpe2pkg_path):
    """Run cpe2pkg tool with given query string.

    The tool returns a list of package name candidates, with confidence score.

    :param query_str: str, query string for cpe2pkg
    :param pkgfile_path: path to a file containing package names;
        this is a set of all possible package names (i.e. all package names in given ecosystem)
    :param cpe2pkg_path: path to a cpe2pkg jar file
    :return: list[str], list of lines returned from cpe2pkg;
        example: ['10.0 package-a', '9.0 package-b']
    """
    logger.info('Running cpe2pkg with query: {q}'.format(q=query_str))

    # run cpe2pkg tool with given query
    cpe2pkg_output = subprocess.check_output(
        'java -jar {cpe2pkg_path} --pkgfile {pkgfile} "{query}"'.format(
            cpe2pkg_path=cpe2pkg_path,
            pkgfile=pkgfile_path,
            query=query_str
        ),
        shell=True,
        universal_newlines=True
    )

    # split on lines and exclude empty lines
    return [x for x in cpe2pkg_output.split('\n') if x]


def build_cpe2pkg_query(vendor, product):
    """Build a query string for cpe2pkg tool.

    :param vendor: list[str], list of possible vendor strings
    :param product: list[str], list of possible product strings
    :return: str, query string for cpe2pkg
    """
    query_template = 'vendor:( {vendor} ) AND product:( {product} )'
    # query string cannot contain colons, replace them with spaces
    p = ' '.join(product).replace(':', ' ')
    v = ' '.join(vendor).replace(':', ' ')
    return query_template.format(vendor=v, product=p)
