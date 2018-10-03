"""Identifier based on nvd-toolkit."""

from toolkit import pipelines
from toolkit.transformers.classifiers import NBClassifier
from toolkit.transformers import feature_hooks

from cvejob.identifiers.basic import NaivePackageNameIdentifier
from cvejob.config import Config
from cvejob.utils import run_cpe2pkg


class NvdToolkitPackageNameIdentifier(NaivePackageNameIdentifier):
    """Identifier based on nvd-toolkit."""

    def identify(self):
        """Identify possible package name candidates."""
        # restored pretrained classifier from the checkpoint
        clf = NBClassifier.restore(checkpoint=Config.nvdtoolkit_export_dir)

        hooks = [
            feature_hooks.has_uppercase_hook,
            feature_hooks.is_alnum_hook,
            feature_hooks.ver_follows_hook,
            feature_hooks.word_len_hook
        ]

        pipeline = pipelines.get_prediction_pipeline(
            classifier=clf,
            feature_hooks=hooks
        )

        results = pipeline.fit_predict(
            [self._doc.description], classifier__sample=True
        ).tolist()[0]

        candidates = [x[0][0] for x in results]

        ecosystem = Config.ecosystem
        if ecosystem == 'java':
            vendor = candidates
        else:
            vendor = [ecosystem]
        product = candidates

        return run_cpe2pkg(vendor, product)
