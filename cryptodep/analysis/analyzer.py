from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import warnings
from pathlib import Path
from typing import Any

from cryptodep.tools.llm_tools import call_llm

_PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NOT_REQUIRED": 4, "UNKNOWN": 5}


def _normalize(value: str) -> str:
    """Strip enum class prefix: 'MigrationPriority.CRITICAL' → 'CRITICAL'."""
    return value.split(".")[-1] if "." in value else value


class CBOMAnalyzer:
    """Parse a CycloneDX CBOM file and produce a structured Markdown report."""

    def __init__(self, cbom_path: Path, db_path: Path | None = None) -> None:
        self.cbom_path = cbom_path
        self.db_path = db_path
        self._cbom: dict[str, Any] = {}
        self._components: list[dict] = []
        self._nodes: list[dict] = []
        self._edges: list[dict] = []
        self._has_sqlite = False
        self._run_id: str | None = None
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        raw = json.loads(self.cbom_path.read_text())
        self._cbom = raw
        self._components = raw.get("components", [])

        # Extract run_id prefix from filename: cbom_cf9e3305.json → cf9e3305
        stem = self.cbom_path.stem
        m = re.match(r"^cbom_([a-f0-9]+)$", stem)
        self._run_id = m.group(1) if m else None

        if self.db_path and self.db_path.exists() and self._run_id:
            self._load_sqlite()

        self._loaded = True

    def _load_sqlite(self) -> None:
        conn = sqlite3.connect(str(self.db_path))
        try:
            cur = conn.cursor()
            # Anti-poisoning: exact prefix match only — no fallback to latest run
            cur.execute(
                "SELECT run_id FROM cdg_runs WHERE run_id LIKE ?",
                (f"{self._run_id}%",),
            )
            row = cur.fetchone()
            if not row:
                warnings.warn(
                    f"[analyze] run_id prefix '{self._run_id}' not found in {self.db_path}. "
                    "Section C (component map) will be skipped.",
                    stacklevel=3,
                )
                return

            full_run_id = row[0]
            cur.execute(
                "SELECT node_id, label, node_type, source_ref FROM cdg_nodes WHERE run_id = ?",
                (full_run_id,),
            )
            self._nodes = [
                {"node_id": r[0], "label": r[1], "node_type": r[2], "source_ref": r[3]}
                for r in cur.fetchall()
            ]
            cur.execute(
                "SELECT source_id, target_id, edge_type, confidence FROM cdg_edges WHERE run_id = ?",
                (full_run_id,),
            )
            self._edges = [
                {"source_id": r[0], "target_id": r[1], "edge_type": r[2], "confidence": r[3]}
                for r in cur.fetchall()
            ]
            self._has_sqlite = True
        finally:
            conn.close()

    def _get_prop(self, component: dict, name: str) -> str:
        for p in component.get("properties", []):
            if p["name"] == name:
                return _normalize(p["value"])
        return ""

    def _crypto_algo_components(self) -> list[dict]:
        """Return cryptographic-asset components with migration_priority (excludes PQC nodes)."""
        return [
            c for c in self._components
            if c.get("type") == "cryptographic-asset"
            and any(p["name"] == "cryptodep:migration_priority" for p in c.get("properties", []))
            and not any(p["name"] == "cryptodep:algorithm_id" for p in c.get("properties", []))
        ]

    def _section_a(self) -> str:
        algos = self._crypto_algo_components()
        critical = [c for c in algos if self._get_prop(c, "cryptodep:migration_priority") == "CRITICAL"]
        high = [c for c in algos if self._get_prop(c, "cryptodep:migration_priority") == "HIGH"]
        safe = [c for c in algos if self._get_prop(c, "cryptodep:migration_priority") == "NOT_REQUIRED"]
        total = len(algos)
        pqc_ready = round(len(safe) / total * 100) if total else 0
        risk = "CRITICAL" if critical else ("HIGH" if high else "MEDIUM")
        ts = self._cbom.get("metadata", {}).get("timestamp", "unknown")
        lines = [
            "# CryptoDep Analysis Report",
            f"**File:** `{self.cbom_path.name}`",
            f"**Scanned:** {ts}",
            f"**Algorithms detected:** {total}",
            f"**PQC Readiness:** {pqc_ready}%",
            f"**Risk level:** {risk}",
        ]
        if critical:
            names = ", ".join(c["name"] for c in critical)
            lines.append(f"**Critical:** {names} — quantum-vulnerable, migrate immediately")
        return "\n".join(lines)

    def _section_b(self) -> str:
        algos = self._crypto_algo_components()
        algos_sorted = sorted(
            algos,
            key=lambda c: _PRIORITY_ORDER.get(self._get_prop(c, "cryptodep:migration_priority"), 99),
        )
        rows = [
            "## Algorithm Risk Table",
            "",
            "| Algorithm | Family | Vuln Class | Migration Priority |",
            "|-----------|--------|------------|--------------------|",
        ]
        for c in algos_sorted:
            name = c["name"]
            family = self._get_prop(c, "cryptodep:algorithm_family")
            vuln = self._get_prop(c, "cryptodep:quantum_vuln_class")
            priority = self._get_prop(c, "cryptodep:migration_priority")
            rows.append(f"| {name} | {family} | {vuln} | {priority} |")
        return "\n".join(rows)

    def _section_c(self) -> str:
        if not self._has_sqlite:
            return ""

        node_label: dict[str, str] = {n["node_id"]: n["label"] for n in self._nodes}
        rows = [
            "## Component Map",
            "",
            "| Component | Uses Algorithm | Edge Type | Confidence |",
            "|-----------|---------------|-----------|------------|",
        ]
        has_rows = False
        for edge in self._edges:
            src_label = node_label.get(edge["source_id"], edge["source_id"])
            tgt_label = node_label.get(edge["target_id"], edge["target_id"])
            conf = edge["confidence"]
            conf_str = f"{conf:.2f}" if conf is not None else "—"
            rows.append(f"| {src_label} | {tgt_label} | {edge['edge_type']} | {conf_str} |")
            has_rows = True

        return "\n".join(rows) if has_rows else ""

    def _section_d(self) -> str:
        from cryptodep.schema.cdg_models import PQC_MIGRATION_TABLE

        algos = self._crypto_algo_components()
        actionable = [
            c for c in algos
            if self._get_prop(c, "cryptodep:migration_priority") not in ("NOT_REQUIRED", "UNKNOWN", "")
        ]
        if not actionable:
            return ""

        lines = ["## PQC Migration Recommendations", ""]
        for c in sorted(
            actionable,
            key=lambda x: _PRIORITY_ORDER.get(self._get_prop(x, "cryptodep:migration_priority"), 99),
        ):
            name = c["name"]
            family = self._get_prop(c, "cryptodep:algorithm_family")
            priority = self._get_prop(c, "cryptodep:migration_priority")
            vuln = self._get_prop(c, "cryptodep:quantum_vuln_class")
            lines.append(f"### {name}")
            lines.append(f"**Priority:** {priority}")
            entry = PQC_MIGRATION_TABLE.get(family)
            if entry:
                rationale = entry.get("rationale", "")
                if rationale:
                    lines.append(f"**Why:** {rationale}")
                for use_case in ("key_exchange", "digital_signature"):
                    if use_case in entry:
                        replacement = entry[use_case]["replacement"].value
                        hybrid = entry[use_case].get("hybrid", "")
                        lines.append(f"**{use_case.replace('_', ' ').title()}:** Replace with `{replacement}`.")
                        if hybrid:
                            lines.append(f"  Hybrid option: {hybrid}")
            elif vuln == "GROVER_WEAKENED":
                lines.append("**Action:** Double the key size to maintain post-quantum security level.")
            else:
                lines.append("**Action:** Evaluate replacement with NIST PQC standards.")
            lines.append("")

        return "\n".join(lines).rstrip()

    def build_base_report(self) -> str:
        parts = [self._section_a(), self._section_b(), self._section_c(), self._section_d()]
        return "\n\n".join(p for p in parts if p)

    def enrich_with_llm(self, config: Any) -> str:
        base = self.build_base_report()
        messages = [{"role": "user", "content": f"Crypto dependency report:\n\n{base}"}]
        system = (
            "You are a post-quantum cryptography migration expert. "
            "Analyze the following crypto dependency report and provide:\n"
            "1. Risk interpretation per algorithm (why it is dangerous)\n"
            "2. Concrete migration steps per component where applicable\n"
            "3. An overall migration priority order\n"
            "Respond in Markdown starting with '## Deep Analysis'."
        )
        try:
            result = asyncio.run(call_llm(config, messages, system_prompt=system, response_format="text"))
            return result.strip()
        except Exception as exc:
            return f"## Deep Analysis\n\n> Deep analysis unavailable: {exc}"

    def write(
        self,
        output_path: Path | None = None,
        deep: bool = False,
        config: Any | None = None,
    ) -> Path:
        self.load()
        report = self.build_base_report()
        if deep and config is not None:
            section_e = self.enrich_with_llm(config)
            report = f"{report}\n\n{section_e}"
        if output_path is None:
            output_path = self.cbom_path.parent / f"{self.cbom_path.stem}_analysis.md"
        output_path.write_text(report)
        return output_path
