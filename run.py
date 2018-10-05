"""Run CVEjob."""

import os
import re

import multiprocessing

import nvdlib
from nvdlib.manager import FeedManager
from nvdlib.query_selectors import in_range

from cvejob.filters.input import validate_cve
from cvejob.config import Config
from cvejob.identifiers import get_identifier
from cvejob.selectors.basic import VersionExistsSelector
from cvejob.outputs.victims import VictimsYamlOutput
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


def run():
    """Run CVEjob."""
    feed_dir = Config.feed_dir
    feed_names = Config.feed_names
    date_range = Config.date_range

    cherrypicked_cve_id = Config.cve_id
    cherrypicked_year = None

    if cherrypicked_cve_id:
        cherrypicked_year = cherrypicked_cve_id.split(sep='-')[1]

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

    if not feed_names:

        if cherrypicked_cve_id:
            feed_names = [cherrypicked_year]

        else:  # load all feeds in the feed_dir
            feed_names = [
                f_name for f_name in os.listdir(feed_dir)
                if re.fullmatch(FEED_NAME_PATTERN, f_name, re.IGNORECASE)
            ]

        if not feed_names:  # if there are still no feed present -> default feed
            logger.info(
                ("No feeds have been selected or found in {f_dir}.\n"
                 "Default feed will be fetched: {default_feed}"
                 ).format(
                    f_dir=feed_dir,
                    default_dir=FeedManager.DEFAULT_FEED_NAME
                ))

    with FeedManager(n_workers=multiprocessing.cpu_count()) as feed_manager:

        feeds = feed_manager.fetch_feeds(
            feed_names=feed_names, data_dir=feed_dir
        )
        collection = feed_manager.collect(feeds)

        if date_range:
            collection_size_before = collection.count()

            collection = collection.find(
                {'published_date': in_range(*date_range)}
            )

            logger.debug(("Filtered out {} Documents that do not fall "
                         "in the given range.").format(
                collection_size_before - collection.count()
            ))

        if cherrypicked_cve_id:

            logger.debug("Cherry-picked CVE `{cve_id}`".format(
                cve_id=cherrypicked_cve_id
            ))
            collection = collection.find(
                {'cve.id_': cherrypicked_cve_id}
            )

        if not collection:  # collection is empty
            logger.info(
                "Collection is empty.".format(
                    picked_cve_id=cherrypicked_cve_id,
                ))

            return

        logger.debug("Number of CVE Documents in the collection: {}".format(
            collection.count()
        ))

        for doc in collection:

            cve_id = doc.cve.id_

            try:

                if not validate_cve(doc):
                    logger.debug(
                        "[{cve_id}] was filtered out by input checks".format(
                            cve_id=cve_id
                        ))
                    continue

                identifier = get_identifier(doc)
                candidates = identifier.identify()

                if not candidates:
                    logger.info(
                        "[{cve_id}] no package name candidates found".format(
                            cve_id=cve_id
                        ))
                    continue

                selector = VersionExistsSelector(doc, candidates)
                winner = selector.pick_winner()

                if not winner:
                    logger.info(
                        "[{cve_id}] no package name found".format(
                            cve_id=cve_id
                        ))
                    continue

                victims_output = VictimsYamlOutput(doc, winner, candidates)
                victims_output.write()

                logger.info(
                    "[{cve_id}] picked `{winner}` out of `{candidates}`".format(
                        cve_id=cve_id,
                        winner=victims_output.winner,
                        candidates=victims_output.candidates
                    ))

            except Exception as exc:
                logger.warning("[{cve_id}]Unexpected exception occured: "
                               "{exc}".format(
                                cve_id=cve_id,
                                exc=exc
                               ))


if __name__ == '__main__':
    run()
