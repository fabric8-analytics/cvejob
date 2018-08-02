"""Benevolent version comparator."""
import re


class BenevolentVersion(object):
    """Benevolent version comparator.

    Release strings (".beta1", "Final") at the end are ignored and so are trailing zeros.

    Examples:
        BenevolentVersion('1.0.0') == BenevolentVersion('1')  # True
        BenevolentVersion('5.0.RELEASE') == BenevolentVersion('5.0.0')  # True

    """

    def __init__(self, version_str):
        """Constructor."""
        self._version_str = version_str
        self._parsed = self._parse()

    @property
    def exact(self):
        """Return exact version string."""
        return self._version_str

    @property
    def loose(self):
        """Return loose version string."""
        return self.__str__()

    def _parse(self):

        # Only parse non-empty strings
        if not isinstance(self._version_str, str) or not self._version_str:
            return tuple([self._version_str])

        result = []

        parts = []
        # Split version string on common version part delimiters (._-)
        for version_part in re.split(r'[._\-]', self._version_str):
            # Split further on decimals
            for part in re.split(r'(\d+)', version_part):
                if part:
                    try:
                        number_part = int(part)
                        parts.append(number_part)
                    except ValueError:
                        # Not a number
                        if parts and isinstance(parts[-1], str):
                            # Two string parts next to each other, concatenate them
                            prev_part = parts.pop()
                            parts.append(prev_part + part)
                        else:
                            parts.append(part)

        if parts and isinstance(parts[0], str):
            return tuple(parts)

        release_string_found = False
        for part in reversed(parts):

            # Exclude trailing zeros
            if not result and not part:
                continue

            # Exclude right-most release string
            if not isinstance(part, int) and not release_string_found:
                release_string_found = True
                result.clear()
                continue

            result.insert(0, part)

        return tuple(result) or (0,)

    def __eq__(self, other):
        return self._parsed == other

    def __ne__(self, other):
        return self._parsed != other

    def __lt__(self, other):
        return self._parsed < other

    def __le__(self, other):
        return self._parsed <= other

    def __gt__(self, other):
        return self._parsed > other

    def __ge__(self, other):
        return self._parsed >= other

    def __repr__(self):
        return "{c}('{v}')".format(c=self.__class__.__qualname__, v=self._version_str)

    def __str__(self):
        return '.'.join([str(x) for x in self._parsed])

    def __hash__(self):
        return hash(self._parsed)
