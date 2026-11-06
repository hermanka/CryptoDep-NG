"""CycloneDX CBOM v1.6 export helpers (PRD Section 5.4).

Operations:
  cdg_to_cbom(cdg_document)   → cyclonedx.model.bom.Bom
  export_cbom_json(bom, path) → write CycloneDX CBOM v1.6 JSON to file
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

log = structlog.get_logger().bind(module="cbom_tools")


def cdg_to_cbom(cdg_document: Any) -> Any:
    """Convert a CDGDocument into a CycloneDX v1.6 Bom object.

    Each CDGNode becomes a CycloneDX Component. CryptoAlgorithm and
    PQCAlgorithm nodes use ComponentType.CRYPTOGRAPHIC_ASSET; all other
    node types use ComponentType.LIBRARY.
    """
    from cyclonedx.model import Property
    from cyclonedx.model.bom import Bom
    from cyclonedx.model.component import Component, ComponentType

    bom = Bom()

    for node_dict in cdg_document.nodes:
        node_type = node_dict.get("node_type", "")
        name = node_dict.get("label", "unknown")
        node_id = node_dict.get("node_id", "")

        if node_type in ("CryptoAlgorithm", "PQCAlgorithm"):
            comp_type = ComponentType.CRYPTOGRAPHIC_ASSET
        else:
            comp_type = ComponentType.LIBRARY

        # Build per-type properties
        properties: list[Property] = []
        if node_type == "CryptoAlgorithm":
            properties = [
                Property(name="cryptodep:algorithm_family",
                         value=str(node_dict.get("algorithm_family", ""))),
                Property(name="cryptodep:quantum_vuln_class",
                         value=str(node_dict.get("quantum_vuln_class", ""))),
                Property(name="cryptodep:migration_priority",
                         value=str(node_dict.get("migration_priority", ""))),
            ]
        elif node_type == "PQCAlgorithm":
            properties = [
                Property(name="cryptodep:algorithm_id",
                         value=str(node_dict.get("algorithm_id", ""))),
                Property(name="cryptodep:fips_standard",
                         value=str(node_dict.get("fips_standard", ""))),
            ]

        component = Component(
            name=name,
            type=comp_type,
            bom_ref=node_id,
            properties=properties or None,
        )
        bom.components.add(component)

    log.info("cbom_built", component_count=len(bom.components))
    return bom


def export_cbom_json(bom: Any, path: str) -> None:
    """Serialize a CycloneDX Bom to JSON (schema version 1.6) at the given path."""
    from cyclonedx.output import make_outputter, OutputFormat
    from cyclonedx.schema import SchemaVersion

    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    json_str = outputter.output_as_string()
    Path(path).write_text(json_str, encoding="utf-8")
    log.info("cbom_exported", path=path, size_bytes=len(json_str))
