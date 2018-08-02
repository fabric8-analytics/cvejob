"""Test cvejob.version.BenevolentVersion."""
from cvejob.version import BenevolentVersion


def test_version_basic():
    """Test basic behavior."""
    assert BenevolentVersion('1') == BenevolentVersion('1')
    assert BenevolentVersion('1') != BenevolentVersion('2')
    assert BenevolentVersion('1') < BenevolentVersion('2')
    assert BenevolentVersion('1') <= BenevolentVersion('2')
    assert BenevolentVersion('1') > BenevolentVersion('0')
    assert BenevolentVersion('1') >= BenevolentVersion('0')

    assert BenevolentVersion(None) != BenevolentVersion('')
    assert BenevolentVersion(None) == BenevolentVersion(None)
    assert BenevolentVersion('0') != BenevolentVersion('')
    assert BenevolentVersion('') == BenevolentVersion('')
    assert BenevolentVersion(1) == BenevolentVersion(1)


def test_version_trailing_zeros():
    """Test with trailing zeros."""
    assert BenevolentVersion('1.0.0.0.0') == BenevolentVersion('1.0')
    assert BenevolentVersion('1.0.1') != BenevolentVersion('1.0.0')
    assert BenevolentVersion('1.1.0') < BenevolentVersion('1.2.0')
    assert BenevolentVersion('1.1.0') <= BenevolentVersion('1.2.0')
    assert BenevolentVersion('1.2.1.1') > BenevolentVersion('1.2.0')
    assert BenevolentVersion('1.2.1.1') >= BenevolentVersion('1.2.1.0')


def test_version_complex():
    """More complex tests."""
    assert BenevolentVersion('0.3m') == BenevolentVersion('0.3.0')
    assert BenevolentVersion('0.3m1') == BenevolentVersion('0.3')
    assert BenevolentVersion('0.3-SNAPSHOT-1') == BenevolentVersion('0.3')
    assert BenevolentVersion('1.2.Final') == BenevolentVersion('1.2.0')


def test_version_exact():
    """Test exact version."""
    assert '1.5.0.RELEASE-1' == BenevolentVersion('1.5.0.RELEASE-1').exact


def test_version_loose():
    """Test loose version."""
    assert '1.5' == BenevolentVersion('1.5.0.RELEASE-1').loose


def test_hash():
    """Test hashing."""
    s = {
        BenevolentVersion('1.0'),
        BenevolentVersion('1'),
        BenevolentVersion(None)
    }
    assert len(s) == 2
