"""Tests for directed symbolic execution."""
import math
import pytest
from unittest.mock import MagicMock


def test_directed_analyzer_init():
    from dynpathresolver.core.directed import DirectedAnalyzer
    mock_project = MagicMock()
    analyzer = DirectedAnalyzer(mock_project)
    assert analyzer.project == mock_project
    assert analyzer.target_sites == set()


def test_find_sites_returns_set():
    from dynpathresolver.core.directed import DirectedAnalyzer
    mock_project = MagicMock()
    mock_cfg = MagicMock()
    mock_cfg.kb.functions = {}
    mock_project.analyses.CFGFast.return_value = mock_cfg
    analyzer = DirectedAnalyzer(mock_project)
    result = analyzer.find_dynamic_loading_sites()
    assert isinstance(result, set)


def test_directed_explorer_init():
    from dynpathresolver.core.directed import DirectedExploration
    target_sites = {0x1000, 0x2000}
    explorer = DirectedExploration(target_sites)
    assert explorer.target_sites == target_sites
    assert explorer.distances == {}


def test_score_state_unknown_addr():
    from dynpathresolver.core.directed import DirectedExploration
    explorer = DirectedExploration({0x1000})
    explorer.distances = {0x1000: 0}
    mock_state = MagicMock()
    mock_state.addr = 0x9999
    score = explorer.score_state(mock_state)
    assert score == math.inf


def test_score_state_known_addr():
    from dynpathresolver.core.directed import DirectedExploration
    explorer = DirectedExploration({0x1000})
    explorer.distances = {0x1000: 0, 0x2000: 5}
    mock_state = MagicMock()
    mock_state.addr = 0x2000
    assert explorer.score_state(mock_state) == 5


def test_prioritize_sorts_by_distance():
    from dynpathresolver.core.directed import DirectedExploration
    explorer = DirectedExploration({0x1000})
    explorer.distances = {0x1000: 0, 0x2000: 10, 0x3000: 5}
    state1 = MagicMock(); state1.addr = 0x2000
    state2 = MagicMock(); state2.addr = 0x3000
    state3 = MagicMock(); state3.addr = 0x1000
    result = explorer.prioritize([state1, state2, state3])
    assert result[0].addr == 0x1000
    assert result[1].addr == 0x3000
    assert result[2].addr == 0x2000


def test_should_prune_far_state():
    from dynpathresolver.core.directed import DirectedExploration
    explorer = DirectedExploration({0x1000})
    explorer.distances = {0x9999: 500}
    mock_state = MagicMock()
    mock_state.addr = 0x9999
    assert explorer.should_prune(mock_state, max_distance=100) == True


def test_should_prune_close_state():
    from dynpathresolver.core.directed import DirectedExploration
    explorer = DirectedExploration({0x1000})
    explorer.distances = {0x2000: 10}
    mock_state = MagicMock()
    mock_state.addr = 0x2000
    assert explorer.should_prune(mock_state, max_distance=100) == False
