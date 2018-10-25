"""Test cvejob.outputs.victims."""

from cvejob.outputs.victims import get_victims_affected_notation, get_victims_fixedin_notation


def test_get_victims_affected_notation():
    """Test get_victims_affected_notation()."""
    affected_versions = [['1.8'], ['1.9', '2.0'], ['2.2', '2.2.1', '2.2.2']]

    results = get_victims_affected_notation(affected_versions, '0.1', '2.3.1')

    assert len(results) == 3
    assert '==1.8' in results
    assert '<=2.0,1.9' in results
    assert '<=2.2.2,2.2' in results

    affected_versions = [['2.2', '2.2.1', '2.2.2']]

    results = get_victims_affected_notation(affected_versions, '2.2', '2.3.1')
    assert len(results) == 1
    assert '<=2.2.2' in results


def test_get_victims_affected_notation_empty():
    """Test get_victims_affected_notation() for empty range."""
    affected_versions = [[]]

    results = get_victims_affected_notation(affected_versions, '0.1', '2.3.1')
    assert not results


def test_get_victims_fixedin_notation():
    """Test get_victims_fixedin_notation()."""
    fixedin_versions = [['0.1', '0.2'], ['0.2.2'], ['1.8', '1.8.1', '1.8.2'], ['2.3', '2.3.1']]

    results = get_victims_fixedin_notation(fixedin_versions, '0.1', '2.3.1')

    assert len(results) == 3
    assert '==0.2.2' in results
    assert '<=1.8.2,1.8' in results
    assert '>=2.3' in results


def test_get_victims_fixedin_notation_empty():
    """Test get_victims_fixedin_notation() for empty range."""
    fixedin_versions = [[]]

    results = get_victims_fixedin_notation(fixedin_versions, '0.1', '2.3.1')
    assert not results
