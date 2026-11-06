"""Agent 3 — Dependency Reasoning Agent (PRD Section 5.3).

Responsibility:
  Infer semantic dependency chains between validated crypto findings.
  Uses chain-of-thought prompting with deterministic import-graph validation
  to mitigate hallucinations (LLMDFA-inspired two-phase approach).

Acceptance criteria (M3):
  AC-A3-01: Multi-hop recall >= 0.70 on 3+-hop chains
  AC-A3-02: Edge hallucination rate < 15%
  AC-A3-03: Avg LLM tokens per dependency chain <= 3000
  AC-A3-04: Processing time < 10 min per 10k LOC on claude-sonnet-4-6
"""
from __future__ import annotations

import json
import re
import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Tuple

import structlog

from cryptodep.agents import BaseAgent
from cryptodep.schema.cdg_models import CDGEdge, CDGEdgeType
from cryptodep.schema.pqc_lookup import QUANTUM_VULNERABLE_FAMILIES
from cryptodep.tools.ast_tools import source_ref_path
from cryptodep.state import CDGState, CryptoFinding
from cryptodep.tools.llm_tools import build_cpg_slice, call_llm

log = structlog.get_logger().bind(agent_name="A3:DependencyReasoning")

# Known crypto library import prefixes — mirrors A4's _CRYPTO_LIB_PREFIXES.
# Used in the FQCN shortcut to accept LLM-proposed edges to crypto classes
# whose package is wildcard-imported (e.g., "org.bouncycastle.jce.provider.*").
_CRYPTO_LIB_IMPORT_PREFIXES: tuple[str, ...] = (
    "java.security", "javax.crypto", "javax.net.ssl",
    "org.bouncycastle", "com.nimbusds", "org.spongycastle",
    "io.jsonwebtoken", "org.jose4j", "org.jasypt",
    "org.apache.commons.crypto", "org.conscrypt",
    "com.google.crypto", "dev.paseto",
    # Python
    "cryptography", "jwt", "pycryptodome", "passlib", "hmac", "hashlib",
    # JavaScript built-ins
    "crypto", "node:crypto", "webcrypto",
)


def _is_crypto_lib_target(target_ref: str) -> bool:
    """Return True if target_ref starts with a known crypto library prefix."""
    return any(
        target_ref == prefix or target_ref.startswith(prefix + ".") or target_ref.startswith(prefix + "/")
        for prefix in _CRYPTO_LIB_IMPORT_PREFIXES
    )


def _source_imports_crypto_prefix(
    source_file: str,
    target_ref: str,
    import_graph: Dict[str, List[str]],
) -> bool:
    """Return True if the source file's imports cover the target's crypto lib package.

    Handles two cases:
    1. Wildcard imports: 'org.bouncycastle.jce.provider.*' covers any class in that package.
    2. Parent-package imports: 'cryptography.hazmat.primitives.asymmetric' covers
       'cryptography.hazmat.primitives.asymmetric.rsa'.
    """
    source_imports = import_graph.get(source_file, [])
    for imp in source_imports:
        # Strip wildcard suffix for comparison
        imp_base = imp.removesuffix(".*")
        # Check: target starts with the import base (package match)
        if target_ref == imp_base or target_ref.startswith(imp_base + "."):
            return True
        # Exact match (already handled by BFS, but safe to recheck)
        if imp == target_ref:
            return True
    return False


_SYSTEM_PROMPT = (
    "You are analyzing cryptographic dependency chains in enterprise code.\n"
    "Trace how cryptographic algorithms flow through the codebase.\n"
    "For each dependency relationship, cite the EXACT file and line number.\n"
    "Think step by step internally, then output ONLY a valid JSON array — no prose, "
    "no markdown, no explanation outside the JSON structure.\n"
    "Only claim dependencies you can directly verify in the code."
)


def _import_matches_target(imp: str, target: str) -> bool:
    """Return True if import string `imp` refers to `target`.

    Handles exact match, stem match (dot-separated), and file extensions:
      "org.bouncycastle.jce.provider.BouncyCastleProvider" matches "BouncyCastleProvider"
      "com.example.CryptoUtil"                             matches "CryptoUtil.java"
    """
    if imp == target:
        return True
    target_stem = Path(target).stem   # "CryptoUtil.java" -> "CryptoUtil", "RSA" -> "RSA"
    return (
        imp == target_stem
        or imp.endswith(f".{target_stem}")
        or imp.endswith(f"/{target_stem}")
    )


def _build_import_graph_support(
    source_file: str,
    target_ref: str,
    import_graph: Dict[str, List[str]],
    max_hops: int = 4,
) -> float:
    """BFS over import_graph to score how well a proposed edge is supported.

    Returns:
      1.0   — same file or direct import (1 hop)
      1/N   — reachable via N hops through local files in the graph
      0.0   — no import path found (hallucination signal)
    """
    if source_file == target_ref:
        return 1.0

    # ── Exact-import check (1 hop) ────────────────────────────────────────────
    # Before BFS, check if the target_ref appears directly in source's import list.
    # This covers the common case and preserves score=1.0 for exact matches.
    for imp in import_graph.get(source_file, []):
        if _import_matches_target(imp, target_ref):
            return 1.0

    # ── Crypto-lib FQCN shortcut ─────────────────────────────────────────────
    # Java wildcard imports ('org.bouncycastle.jce.provider.*') and Python
    # from-imports ('from cryptography.hazmat.primitives.asymmetric import rsa')
    # store the package/module path, not the class name.  The BFS below can't
    # match a FQCN target against a wildcard import string.
    # Shortcut: if the target is a known crypto lib class AND the source file
    # imports its parent package (possibly with a wildcard), accept the edge
    # with high confidence (0.9 = equivalent to a verified 1-hop dependency).
    if _is_crypto_lib_target(target_ref) and _source_imports_crypto_prefix(
        source_file, target_ref, import_graph
    ):
        return 0.9

    # Build reverse map: any import-string match for a local file -> that file's path
    # This handles the case where import_graph keys are file paths but import strings are FQCNs
    _local_files = list(import_graph.keys())

    queue: deque[tuple[str, int]] = deque([(source_file, 1)])
    visited: set[str] = {source_file}

    while queue:
        current, hops = queue.popleft()
        if hops > max_hops:
            continue
        for imp in import_graph.get(current, []):
            if _import_matches_target(imp, target_ref):
                return round(1.0 / hops, 3)
            # Traverse to local files: check if imp matches any import_graph key
            for local_file in _local_files:
                if local_file not in visited and _import_matches_target(imp, local_file):
                    visited.add(local_file)
                    queue.append((local_file, hops + 1))

    return 0.0


def _extract_file_and_line(source_ref: str) -> Tuple[str, int]:
    """Parse 'path/file.java:L42' or 'path/file.java:42' -> (file_path, line_number)."""
    parts = source_ref.rsplit(":", 1)
    file_path = parts[0]
    if len(parts) < 2:
        return file_path, 1
    line_str = parts[1].lstrip("L")
    try:
        return file_path, int(line_str)
    except ValueError:
        return file_path, 1


def _build_dependency_prompt(
    findings: List[CryptoFinding],
    import_graph: Dict[str, List[str]],
    ast_cache: Dict[str, Any],
    config: Any,
) -> Tuple[str, str]:
    """Return (system_prompt, user_prompt) for the A3 CoT reasoning call."""
    # Filter to quantum-vulnerable families only for the main findings block.
    # Rationale: AES/SHA/HMAC have no dependency chains relevant to PQC migration.
    # Fallback: if no quantum-vulnerable findings, use all (do not silently drop everything).
    _MAX_FINDINGS = 30
    _MAX_SAFE_HINTS = 20
    vuln_findings = [
        f for f in findings
        if f.get("algorithm_family", "").upper() in QUANTUM_VULNERABLE_FAMILIES
    ]
    safe_findings = [
        f for f in findings
        if f.get("algorithm_family", "").upper() not in QUANTUM_VULNERABLE_FAMILIES
    ]
    findings_for_prompt = vuln_findings if vuln_findings else list(findings)
    findings_capped = sorted(findings_for_prompt, key=lambda f: f["confidence"], reverse=True)[:_MAX_FINDINGS]
    findings_json = json.dumps(list(findings_capped), separators=(",", ":"))

    # Compact hints for quantum-safe findings — structural context only (~15 tokens each).
    # These let A3 see file+line evidence for AES/SHA without token budget explosion.
    safe_hints = [
        {"f": source_ref_path(f["source_ref"]), "l": f["source_ref"].rsplit(":", 1)[-1].lstrip("L"), "a": f.get("parameter_set") or f["algorithm_family"]}
        for f in safe_findings[:_MAX_SAFE_HINTS]
    ]
    safe_hints_json = json.dumps(safe_hints, separators=(",", ":")) if safe_hints else "[]"

    # Prioritize import graph: files with crypto findings first, then alphabetical.
    relevant_files = {source_ref_path(f["source_ref"]) for f in findings_capped}
    sorted_ig_keys = sorted(
        import_graph.keys(),
        key=lambda k: (k not in relevant_files, k)
    )

    max_ig = getattr(config, "max_import_graph_entries", 50)
    if len(sorted_ig_keys) > max_ig:
        log.warning(
            "a3_import_graph_truncated",
            total=len(sorted_ig_keys),
            kept=max_ig,
        )
    ig_excerpt = {k: import_graph[k] for k in sorted_ig_keys[:max_ig]}
    ig_json = json.dumps(ig_excerpt, separators=(",", ":"))

    # Build CPG slices for files that appear in findings.
    # Cap at 3 unique files, 300 tokens each, to keep payload within provider limits.
    _MAX_SLICE_FILES = 3
    _MAX_SLICE_TOKENS = 300
    slices: List[str] = []
    seen_files: set[str] = set()
    for f in findings_capped:
        if len(seen_files) >= _MAX_SLICE_FILES:
            break
        file_path, line = _extract_file_and_line(f["source_ref"])
        if file_path in seen_files:
            continue
        seen_files.add(file_path)
        if file_path in ast_cache:
            snippet = build_cpg_slice(ast_cache, file_path, line, max_tokens=_MAX_SLICE_TOKENS)
            if snippet:
                slices.append(f"=== {file_path}:L{line} ===\n{snippet}")
    file_slices = "\n\n".join(slices)

    safe_hints_section = (
        f"Quantum-safe findings (structural context ONLY — no PQC migration needed. "
        f"do NOT propose dependency edges from these files unless the import graph "
        f"above shows a direct import path. These are reference entries, not "
        f"inference targets):\n{safe_hints_json}\n\n"
        if safe_hints else ""
    )
    user_prompt = (
        f"Crypto findings to analyze:\n{findings_json}\n\n"
        f"{safe_hints_section}"
        f"Import graph for context:\n{ig_json}\n\n"
        f"Relevant file slices:\n{file_slices}\n\n"
        "Output ONLY a JSON array of dependency edges. "
        "Each element must have exactly these fields:\n"
        '[\n  {"edge_type": "uses|implements|depends_on|relies_on|protects",\n'
        '   "source_ref": "path/file.java:L42",\n'
        '   "target_ref": "import.path.or.file",\n'
        '   "source_label": "ComponentName",\n'
        '   "target_label": "TargetName",\n'
        '   "llm_confidence": 0.9,\n'
        '   "evidence": "exact code snippet or import statement"}\n]\n\n'
        "Return [] if no verifiable dependency chains exist. "
        "Do not include any text outside the JSON array."
    )
    return _SYSTEM_PROMPT, user_prompt


def _parse_llm_edges(llm_response: str) -> List[Dict[str, Any]]:
    """Extract the JSON edge list from an LLM response.

    Handles code fences (```json ... ```) and CoT preamble before the array.
    Returns [] on parse failure.
    """
    text = llm_response.strip()
    # Strip outer code fence only if it wraps the whole response
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
    text = text.strip()
    start = text.find("[")
    if start == -1:
        return []
    try:
        result, _ = json.JSONDecoder().raw_decode(text, start)
        return result if isinstance(result, list) else []
    except json.JSONDecodeError:
        log.warning("a3_edge_parse_error", preview=text[:200])
        return []


class DependencyReasoningAgent(BaseAgent):
    agent_name = "A3:DependencyReasoning"

    async def run(self, state: CDGState) -> CDGState:
        t0 = time.time()
        findings: List[CryptoFinding] = state["validated_findings"]
        import_graph: Dict[str, List[str]] = state.get("import_graph", {})
        ast_cache: Dict[str, Any] = state.get("ast_cache", {})

        if not findings:
            self.log.info("a3_skip_no_findings")
            state.update({"candidate_edges": [], "validated_edges": []})
            return state

        self.log.info("a3_start", finding_count=len(findings))

        system_prompt, user_prompt = _build_dependency_prompt(
            findings, import_graph, ast_cache, self.config
        )
        errors = list(state.get("errors", []))
        self.log.info("a3_llm_request", prompt_chars=len(user_prompt))
        try:
            llm_response = await call_llm(
                self.config,
                [{"role": "user", "content": user_prompt}],
                system_prompt=system_prompt,
            )
        except Exception as exc:  # noqa: BLE001
            self.log.warning("a3_llm_fail", reason=str(exc)[:120])
            errors.append({
                "agent": self.agent_name,
                "error_type": "llm_call_failed",
                "message": str(exc)[:200],
                "recoverable": True,
            })
            state.update({"candidate_edges": [], "validated_edges": [], "errors": errors})
            return state

        # Rough token estimate: ~4 chars per token
        token_estimate = (len(user_prompt) + len(llm_response)) // 4

        proposed = _parse_llm_edges(llm_response)
        if not proposed and llm_response.strip() and llm_response.strip() not in ("[]", "[ ]"):
            errors.append({
                "agent": self.agent_name,
                "error_type": "llm_parse_failure",
                "message": f"LLM returned unparseable edge list (preview: {llm_response[:100]})",
                "recoverable": True,
            })
        candidate_edges: List[CDGEdge] = []
        validated_edges: List[CDGEdge] = []

        for edge_data in proposed:
            try:
                edge_type_raw = edge_data.get("edge_type", "depends_on")
                # Normalize common LLM variations to canonical CDGEdgeType
                edge_type_norm = edge_type_raw.lower()
                if edge_type_norm in ("imports", "references", "includes"):
                    edge_type = CDGEdgeType.DEPENDS_ON
                elif edge_type_norm in ("calls", "invokes"):
                    edge_type = CDGEdgeType.USES
                else:
                    edge_type = CDGEdgeType(edge_type_norm)
            except (KeyError, ValueError):
                self.log.warning("a3_unknown_edge_type", data=str(edge_data)[:100])
                continue

            source_ref: str = edge_data.get("source_ref", "")
            target_ref: str = edge_data.get("target_ref", "")
            source_file, _ = _extract_file_and_line(source_ref)
            llm_confidence = float(edge_data.get("llm_confidence", 0.8))

            support = _build_import_graph_support(
                source_file, target_ref, import_graph, self.config.max_hop_depth
            )

            candidate_edges.append(CDGEdge(
                edge_type=edge_type,
                source_id=source_ref or edge_data.get("source_label", "unknown"),
                target_id=target_ref or edge_data.get("target_label", "unknown"),
                confidence=round(
                    min(llm_confidence, support if support > 0 else llm_confidence), 3
                ),
                evidence=edge_data.get("evidence"),
            ))

            if support > self.config.min_edge_support:
                validated_edges.append(CDGEdge(
                    edge_type=edge_type,
                    source_id=source_ref or edge_data.get("source_label", "unknown"),
                    target_id=target_ref or edge_data.get("target_label", "unknown"),
                    confidence=round(min(llm_confidence, support), 3),
                    evidence=edge_data.get("evidence"),
                ))
                self.log.info(
                    "a3_edge_validated",
                    edge_type=edge_type.value,
                    source=source_ref,
                    target=target_ref,
                    confidence=round(min(llm_confidence, support), 3),
                )
            else:
                self.log.warning(
                    "a3_edge_hallucination",
                    edge_type=edge_type.value,
                    source=source_ref,
                    target=target_ref,
                )

        if candidate_edges:
            h_rate = (len(candidate_edges) - len(validated_edges)) / len(candidate_edges)
            self.log.info(
                "a3_complete",
                candidates=len(candidate_edges),
                validated=len(validated_edges),
                hallucination_rate=round(h_rate, 3),
            )

        elapsed = time.time() - t0
        state.update({
            "candidate_edges": candidate_edges,
            "validated_edges": validated_edges,
            "agent_timings": {**state.get("agent_timings", {}), self.agent_name: elapsed},
            "total_llm_tokens": state.get("total_llm_tokens", 0) + token_estimate,
            "errors": errors,
        })
        return state
