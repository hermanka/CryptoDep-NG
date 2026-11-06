from __future__ import annotations
import json
import os
import tempfile

from cryptodep.tools.cbom_tools import cdg_to_cbom, export_cbom_json
from cryptodep.schema.cdg_models import (
    CDGDocument,
    CryptoAlgorithmNode,
    PQCAlgorithmNode,
    CDGEdge,
    CDGEdgeType,
    NistQuantumVulnClass,
    PQCAlgorithmId,
    NistSecurityLevel,
    MigrationPlan,
)


def _make_minimal_cdg() -> CDGDocument:
    rsa = CryptoAlgorithmNode(
        label="RSA-2048",
        algorithm_family="RSA",
        parameter_set="RSA-2048",
        quantum_vuln_class=NistQuantumVulnClass.QUANTUM_VULNERABLE,
    )
    mlkem = PQCAlgorithmNode(
        label="ML-KEM-768",
        algorithm_id=PQCAlgorithmId.ML_KEM_768,
        fips_standard="FIPS 203",
        security_level=NistSecurityLevel.L3,
        primitive_type="KEM",
        math_basis="lattice_mlwe",
    )
    edge = CDGEdge(
        edge_type=CDGEdgeType.MIGRATES_TO,
        source_id=rsa.node_id,
        target_id=mlkem.node_id,
    )
    doc = CDGDocument(
        nodes=[rsa.model_dump(mode="python"), mlkem.model_dump(mode="python")],
        edges=[edge],
        migration_plan=MigrationPlan(total_vulnerable_assets=1, quantum_readiness_score=0.0),
    )
    return doc


def test_cdg_to_cbom_returns_bom():
    from cyclonedx.model.bom import Bom
    doc = _make_minimal_cdg()
    bom = cdg_to_cbom(doc)
    assert bom is not None
    assert isinstance(bom, Bom)


def test_cdg_to_cbom_has_components():
    doc = _make_minimal_cdg()
    bom = cdg_to_cbom(doc)
    assert len(bom.components) >= 1


def test_export_cbom_json_writes_valid_json():
    doc = _make_minimal_cdg()
    bom = cdg_to_cbom(doc)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        export_cbom_json(bom, path)
        with open(path) as fh:
            data = json.load(fh)
        assert "bomFormat" in data
        assert data["bomFormat"] == "CycloneDX"
    finally:
        os.unlink(path)


def test_export_cbom_json_includes_crypto_components():
    doc = _make_minimal_cdg()
    bom = cdg_to_cbom(doc)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = f.name
    try:
        export_cbom_json(bom, path)
        with open(path) as fh:
            data = json.load(fh)
        component_names = [c.get("name", "") for c in data.get("components", [])]
        assert any("RSA" in n for n in component_names)
    finally:
        os.unlink(path)
