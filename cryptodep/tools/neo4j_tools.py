"""Neo4j CRUD helpers and Cypher query templates (PRD Section 5.4).

Operations:
  setup_constraints(driver)       → create schema constraints and indexes
  upsert_node(driver, node)       → MERGE CDGNode to Neo4j
  upsert_edge(driver, edge)       → MERGE CDGEdge to Neo4j
  count_nodes_and_edges(driver)   → {"nodes": N, "edges": M}
"""
from __future__ import annotations

from typing import Any

import structlog

from cryptodep.schema.cdg_models import (
    CDGEdge,
    CDGNodeType,
    CryptoAlgorithmNode,
    PQCAlgorithmNode,
    CryptoLibraryNode,
    AppComponentNode,
    BusinessProcessNode,
)

log = structlog.get_logger().bind(module="neo4j_tools")

_CONSTRAINT_QUERIES = [
    "CREATE CONSTRAINT cdg_node_id IF NOT EXISTS FOR (n:CDGNode) REQUIRE n.node_id IS UNIQUE",
    "CREATE INDEX idx_algo_family IF NOT EXISTS FOR (n:CryptoAlgorithm) ON (n.algorithm_family)",
    "CREATE INDEX idx_vuln_class IF NOT EXISTS FOR (n:CryptoAlgorithm) ON (n.quantum_vuln_class)",
    "CREATE INDEX idx_pqc_algo_id IF NOT EXISTS FOR (n:PQCAlgorithm) ON (n.algorithm_id)",
    "CREATE INDEX idx_component_boundary IF NOT EXISTS FOR (n:AppComponent) ON (n.is_boundary)",
]

# Cypher MERGE templates keyed by CDGNodeType
_NODE_MERGE = {
    CDGNodeType.CRYPTO_ALGORITHM: """
        MERGE (n:CDGNode:CryptoAlgorithm {node_id: $node_id})
        SET n += {label: $label, algorithm_family: $algorithm_family,
                  parameter_set: $parameter_set, key_size_bits: $key_size_bits,
                  use_context: $use_context, quantum_vuln_class: $quantum_vuln_class,
                  migration_priority: $migration_priority,
                  migration_urgency_score: $migration_urgency_score,
                  hndl_risk: $hndl_risk, source_ref: $source_ref,
                  confidence: $confidence, detected_by: $detected_by}
    """,
    CDGNodeType.PQC_ALGORITHM: """
        MERGE (n:CDGNode:PQCAlgorithm {node_id: $node_id})
        SET n += {label: $label, algorithm_id: $algorithm_id,
                  fips_standard: $fips_standard, security_level: $security_level,
                  primitive_type: $primitive_type, math_basis: $math_basis}
    """,
    CDGNodeType.CRYPTO_LIBRARY: """
        MERGE (n:CDGNode:CryptoLibrary {node_id: $node_id})
        SET n += {label: $label, library_name: $library_name,
                  version: $version, language: $language,
                  import_path: $import_path, pqc_ready: $pqc_ready,
                  source_ref: $source_ref}
    """,
    CDGNodeType.APP_COMPONENT: """
        MERGE (n:CDGNode:AppComponent {node_id: $node_id})
        SET n += {label: $label, component_type: $component_type,
                  language: $language, file_path: $file_path,
                  owns_crypto: $owns_crypto, is_boundary: $is_boundary,
                  source_ref: $source_ref}
    """,
    CDGNodeType.BUSINESS_PROCESS: """
        MERGE (n:CDGNode:BusinessProcess {node_id: $node_id})
        SET n += {label: $label, criticality: $criticality,
                  bssn_system_id: $bssn_system_id}
    """,
}

# Fallback edge merge without APOC (works for all edge types)
_EDGE_MERGE_SIMPLE = """
    MATCH (src:CDGNode {node_id: $source_id})
    MATCH (tgt:CDGNode {node_id: $target_id})
    MERGE (src)-[r:CDG_EDGE {edge_id: $edge_id}]->(tgt)
    SET r += {edge_type: $rel_type, confidence: $confidence, evidence: $evidence}
"""

_COUNT_QUERY = (
    "MATCH (n:CDGNode) WITH count(n) AS n "
    "OPTIONAL MATCH ()-[e]->() WITH n, count(e) AS e RETURN n, e"
)


def setup_constraints(driver: Any) -> None:
    """Create schema constraints and indexes. Idempotent (IF NOT EXISTS)."""
    with driver.session() as session:
        for q in _CONSTRAINT_QUERIES:
            try:
                session.run(q)
            except Exception as exc:  # noqa: BLE001
                log.warning("neo4j_constraint_skip", query=q[:60], reason=str(exc)[:80])


def upsert_node(driver: Any, node: Any) -> None:
    """MERGE a CDGNode subtype into Neo4j."""
    query = _NODE_MERGE.get(node.node_type)
    if query is None:
        log.warning("neo4j_upsert_unknown_type", node_type=node.node_type)
        return
    # Flatten to dict and convert enum values to their primitive representations
    params = node.model_dump(mode="python")
    params = {k: (v.value if hasattr(v, "value") else v) for k, v in params.items()}
    with driver.session() as session:
        session.run(query, **params)


def upsert_edge(driver: Any, edge: CDGEdge) -> None:
    """MERGE a CDGEdge into Neo4j using a generic labeled relationship."""
    params = {
        "source_id": edge.source_id,
        "target_id": edge.target_id,
        "rel_type": edge.edge_type.value.upper(),
        "edge_id": edge.edge_id,
        "confidence": edge.confidence,
        "evidence": edge.evidence or "",
    }
    with driver.session() as session:
        session.run(_EDGE_MERGE_SIMPLE, **params)


def count_nodes_and_edges(driver: Any) -> dict:
    """Return total node and edge counts from Neo4j."""
    with driver.session() as session:
        result = session.run(_COUNT_QUERY).single()
        if result:
            return {"nodes": result["n"], "edges": result["e"]}
        return {"nodes": 0, "edges": 0}


def clear_neo4j(driver: Any) -> dict:
    """Delete ALL nodes and relationships from Neo4j.

    Used by preflight and eval --clear-neo4j to ensure a clean slate
    before each run, preventing cross-run data accumulation.

    Returns:
        dict with 'nodes_deleted' and 'rels_deleted' counts.
    """
    _DELETE_ALL = (
        "MATCH (n) "
        "OPTIONAL MATCH (n)-[r]-() "
        "WITH n, r, count(r) AS rel_count "
        "DELETE r "
        "WITH n, rel_count "
        "DELETE n "
        "RETURN count(n) AS nodes_deleted, sum(rel_count) AS rels_deleted"
    )
    # Neo4j batches large deletes to avoid OOM; use CALL IN TRANSACTIONS for big graphs.
    _DELETE_BATCHED = (
        "CALL { "
        "MATCH (n) "
        "DETACH DELETE n "
        "} IN TRANSACTIONS OF 1000 ROWS"
    )
    with driver.session() as session:
        try:
            # Try batched delete first (Neo4j 5.x)
            session.run(_DELETE_BATCHED)
        except Exception:  # noqa: BLE001
            # Fall back to simple DETACH DELETE (Neo4j 4.x)
            session.run("MATCH (n) DETACH DELETE n")
    # Count what remains (should be 0)
    stats = count_nodes_and_edges(driver)
    log.info(
        "neo4j_cleared",
        remaining_nodes=stats["nodes"],
        remaining_edges=stats["edges"],
    )
    return {"nodes_deleted": stats["nodes"], "rels_deleted": stats["edges"]}
