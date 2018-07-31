"""Run CVEjob."""

import json
import logging

from nvdlib.model import CVE

from cvejob.filters.input import validate_cve
from cvejob.config import Config
from cvejob.identifiers import get_identifier
from cvejob.selectors.basic import VersionExistsSelector
from cvejob.outputs.victims import VictimsYamlOutput

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('cvejob')


def run():
    """Run CVEjob."""
    with open(Config.feed_path, encoding='utf-8') as f:
        cherrypicked_cve_id = Config.cve_id

        feed = json.load(f)

        for cve_dict in feed.get('CVE_Items'):
            cve = CVE.from_dict(cve_dict)
            logger.info('{cve_id} found'.format(cve_id=cve.cve_id))

            try:
                if cherrypicked_cve_id and cve.cve_id != cherrypicked_cve_id:
                    # we are only interested in the cherry-picked CVE ID
                    logger.info('{cve_id} not cherry-picked, skipping')
                    continue

                if not validate_cve(cve):
                    logger.info(
                        '{cve_id} was filtered out by input checks'.format(cve_id=cve.cve_id)
                    )
                    continue

                identifier = get_identifier(cve)
                candidates = identifier.identify()

                if not candidates:
                    logger.info(
                        '{cve_id} no package name candidates found'.format(cve_id=cve.cve_id)
                    )
                    continue

                selector = VersionExistsSelector(cve, candidates)
                winner = selector.pick_winner()

                if not winner:
                    logger.info('{cve_id} no package name found'.format(cve_id=cve.cve_id))
                    continue

                VictimsYamlOutput(cve, winner, candidates).write()
            finally:
                if cherrypicked_cve_id and cve.cve_id == cherrypicked_cve_id:
                    # we found what we were looking for, skip the rest
                    break


if __name__ == '__main__':
    run()
