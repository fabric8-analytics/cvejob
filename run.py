"""Run CVEjob."""

import os
import re

import logging

import multiprocessing

from nvdlib.manager import FeedManager

from cvejob.filters.input import validate_cve
from cvejob.config import Config
from cvejob.identifiers import get_identifier
from cvejob.selectors.basic import VersionExistsSelector
from cvejob.outputs.victims import VictimsYamlOutput


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('cvejob')

FEED_NAME_PATTERN = r"nvdcve-" \
                    r"(?P<version>[\d.]+)-" \
                    r"(?P<name>(?P<name_string>(([A-Za-z]+)))|(?P<name_year>([\d]+)))" \
                    r".json"


def run():
    """Run CVEjob."""
    feed_dir = Config.feed_dir
    feed_names = Config.feed_names

    if not feed_names:
        # load all feeds in the feed_dir

        feed_names = [
            f_name for f_name in os.listdir(feed_dir)
            if re.fullmatch(FEED_NAME_PATTERN, f_name, re.IGNORECASE)
        ]

        if not feed_names:
            logger.error("Feeds have not been found in {}".format(feed_dir))

    with FeedManager(n_workers=multiprocessing.cpu_count()) as feed_manager:

        feeds = feed_manager.fetch_feeds(
            feed_names=feed_names, data_dir=feed_dir
        )
        collection = feed_manager.collect(feeds)

        cherrypicked_cve_id = Config.cve_id

        if cherrypicked_cve_id:
            logger.debug("Cherry-picked CVE `{cve_id}`".format(
                cve_id=cherrypicked_cve_id
            ))
            collection = collection.find(
                {'cve.id_': cherrypicked_cve_id}
            )
            logger.debug("Number of CVE Documents in the collection: {}".format(
                collection.count()
            ))

            if not collection:  # collection is empty
                logger.info(
                    "[{picked_cve_id}] was not found in the collection of feeds:"
                    "{feed_names}".format(
                        picked_cve_id=cherrypicked_cve_id,
                        feed_names=feed_names
                    ))

                return

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

                print('Candidates:', candidates)

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
