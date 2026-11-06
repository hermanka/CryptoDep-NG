from __future__ import annotations
import json
import pytest
from unittest.mock import MagicMock, call, patch

from cryptodep.tools.neo4j_tools import (
    setup_constraints,
    upsert_node,
    upsert_edge,
    count_nodes_and_edges,
)
from cryptodep.schema.cdg_models import (
    CryptoAlgorithmNode,
    CDGEdge,
    CDGEdgeType,
    NistQuantumVulnClass,
    DetectionMethod,
    CDGNodeType,
)


def _make_driver():
    """Return a mock neo4j driver that tracks run() calls."""
    session = MagicMock()
    driver = MagicMock()
    driver.session.return_value.__enter__ = MagicMock(return_value=session)
    driver.session.return_value.__exit__ = MagicMock(return_value=False)
    return driver, session


def test_setup_constraints_runs_cypher():
    driver, session = _make_driver()
    setup_constraints(driver)
    assert session.run.call_count >= 3  # constraint + at least 2 indexes


def test_upsert_node_calls_run_with_node_id():
    driver, session = _make_driver()
    node = CryptoAlgorithmNode(
        label="RSA-2048",
        algorithm_family="RSA",
        parameter_set="RSA-2048",
        key_size_bits=2048,
        quantum_vuln_class=NistQuantumVulnClass.QUANTUM_VULNERABLE,
    )
    upsert_node(driver, node)
    assert session.run.called
    call_args = session.run.call_args
    assert node.node_id in str(call_args)


def test_upsert_edge_calls_run_with_edge_id():
    driver, session = _make_driver()
    edge = CDGEdge(
        edge_type=CDGEdgeType.MIGRATES_TO,
        source_id="cdg:node:src",
        target_id="cdg:node:tgt",
        confidence=0.9,
    )
    upsert_edge(driver, edge)
    assert session.run.called
    call_args = session.run.call_args
    assert edge.edge_id in str(call_args)


def test_count_nodes_and_edges_returns_dict():
    driver, session = _make_driver()
    session.run.return_value.single.return_value = {"n": 5, "e": 3}
    result = count_nodes_and_edges(driver)
    assert "nodes" in result
    assert "edges" in result
