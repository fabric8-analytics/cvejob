"""Run CVEjob."""

import sys
from decimal import Decimal
import multiprocessing

import nvdlib
from nvdlib.manager import FeedManager
from nvdlib.query_selectors import in_range

from cvejob.filters.input import validate_cve
from cvejob.config import Config
from cvejob.identifiers import get_identifier_cls
from cvejob.cpe2pkg import get_pkgfile_path, PackageNameCandidate
from cvejob.selectors.basic import VersionSelector
from cvejob.outputs.victims import VictimsYamlOutput
from cvejob.versions import NVDVersions
from cvejob.utils import parse_date_range

import logging


# logging configuration
logging.basicConfig(level=logging.DEBUG,
                    handlers=[nvdlib.get_logging_handler()])  # use nvdlib's handler

logger = logging.getLogger('cvejob')


FEED_NAME_PATTERN = r"nvdcve-" \
                    r"(?P<version>[\d.]+)-" \
                    r"(?P<name>(?P<name_string>(([A-Za-z]+)))|(?P<name_year>([\d]+)))" \
                    r".json"


def _log_results(victims_output):
    """Log results."""
    cve_id = victims_output.cve.id_

    logger.info(
        "[{cve_id}] picked `{winner}` out of `{candidates}`".format(
            cve_id=cve_id,
            winner=victims_output.winner,
            candidates=victims_output.candidates
        ))

    logger.info(
        "[{cve_id}] Affected version range: {version_ranges}".format(
            cve_id=cve_id,
            version_ranges=victims_output.affected_versions
        ))

    logger.info(
        "[{cve_id}] Safe version range: {version_ranges}".format(
            cve_id=cve_id,
            version_ranges=victims_output.safe_versions
        ))


def _filter_collection(collection, date_range, cherry_pick):
    """Filter Document collection."""
    if date_range:
        collection_size_before = collection.count()

        collection = collection.find(
            {'published_date': in_range(*date_range)}
        )

        logger.debug(("Filtered out {} Documents that do not fall "
                      "in the given range.").format(
            collection_size_before - collection.count()
        ))

    if cherry_pick:

        logger.debug("Cherry-picked CVE `{cve_id}`".format(
            cve_id=cherry_pick
        ))
        collection = collection.find(
            {'cve.id_': cherry_pick}
        )

    return collection


def run():
    """Run CVEjob."""
    feed_dir = Config.feed_dir
    feed_names = Config.feed_names
    date_range = Config.date_range

    cherrypicked_cve_id = Config.cve_id
    cherrypicked_year = None

    if cherrypicked_cve_id:
        cherrypicked_year = cherrypicked_cve_id.split(sep='-')[1]

        if int(cherrypicked_year) < 2002:
            # all CVEs prior to 2002 are stored in 2002 feed
            cherrypicked_year = 2002

    if date_range:
        date_range = parse_date_range(Config.date_range)

        feed_names = range(date_range[0].year, date_range[1].year + 1)

        if cherrypicked_cve_id:  # optimization check

            if int(cherrypicked_year) not in feed_names:
                logger.info(
                    "[{picked_cve_id}] does not belong to the given feed range:"
                    " {date_range}".format(
                        picked_cve_id=cherrypicked_cve_id,
                        date_range=date_range
                    ))

                return

            # prune the feed names as it is not necessary to iterate over all of them
            feed_names = [cherrypicked_year]

    if not feed_names:

        if cherrypicked_cve_id:
            feed_names = [cherrypicked_year]
        else:
            feed_names = ['modified']

    with FeedManager(n_workers=multiprocessing.cpu_count()) as feed_manager:

        feeds = feed_manager.fetch_feeds(
            feed_names=feed_names, data_dir=feed_dir, update=True
        )
        collection = feed_manager.collect(feeds)
        collection = _filter_collection(collection,
                                        date_range,
                                        cherrypicked_cve_id)

    if not collection:  # collection is empty
        logger.info(
            "Collection is empty.".format(
                picked_cve_id=cherrypicked_cve_id,
            ))

        return

    logger.debug("Number of CVE Documents in the collection: {}".format(
        collection.count()
    ))

    if Config.package_name and Config.cve_id:
        # user knows the package name, so we don't have to guess ;)
        doc = [x for x in collection][0]  # Collection doesn't support indexing
        affected, safe = NVDVersions(doc, Config.package_name, Config.ecosystem).run()
        victims_output = VictimsYamlOutput(
            ecosystem=Config.ecosystem,
            cve_doc=doc,
            winner=PackageNameCandidate(Config.package_name, Decimal('1.0')),
            candidates=[],
            affected=affected,
            fixedin=safe
        )
        _log_results(victims_output)
        victims_output.write()
        sys.exit(0)

    for doc in collection:

        cve_id = doc.cve.id_

        try:

            if not validate_cve(doc):
                logger.debug(
                    "[{cve_id}] was filtered out by input checks".format(
                        cve_id=cve_id
                    ))
                continue

            pkgfile_path = get_pkgfile_path(Config.pkgfile_dir, Config.ecosystem)
            identifier = get_identifier_cls()(doc, Config.ecosystem, pkgfile_path)
            candidates = identifier.identify()

            if not candidates:
                logger.info(
                    "[{cve_id}] no package name candidates found".format(
                        cve_id=cve_id
                    ))
                continue

            selector = VersionSelector(doc, candidates, Config.ecosystem)
            winner = selector.pick_winner()

            if not winner:
                logger.info(
                    "[{cve_id}] no package name found".format(
                        cve_id=cve_id
                    ))

                continue

            affected, safe = NVDVersions(doc, winner.package, Config.ecosystem).run()

            victims_output = VictimsYamlOutput(
                ecosystem=Config.ecosystem,
                cve_doc=doc,
                winner=winner,
                candidates=candidates,
                affected=affected,
                fixedin=safe
            )

            _log_results(victims_output)

            victims_output.write()

        except Exception as exc:

            logger.warning(
                "[{cve_id}] Unexpected exception occurred: {exc}".format(
                    cve_id=cve_id,
                    exc=exc
                ), exc_info=True)


if __name__ == '__main__':
    run()
