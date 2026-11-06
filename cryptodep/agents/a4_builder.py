"""Agent 4 — CDG Builder Agent (PRD Section 5.4).

Responsibility:
  Assemble all validated nodes and edges into a complete CDGDocument (v1.0 schema).
  Annotate CryptoAlgorithm nodes with NIST PQC vulnerability class.
  Add migrates_to edges from pqc_lookup.PQC_MIGRATION_TABLE.
  Compute betweenness centrality (networkx), update urgency scores.
  Persist CDG to Neo4j. Export CycloneDX CBOM v1.6 JSON.

Acceptance criteria (M4):
  AC-A4-01: Schema validation pass rate = 100%
  AC-A4-02: Neo4j import completes without constraint violations
  AC-A4-03: CBOM export is valid CycloneDX v1.6 JSON
  AC-A4-04: All quantum_vulnerable nodes have at least one migrates_to edge
"""
from __future__ import annotations

import os
import re
import time
import uuid
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set, Tuple

import networkx as nx
import structlog

from cryptodep.agents import BaseAgent
from cryptodep.schema.cdg_models import (
    AppComponentNode,
    CDGDocument,
    CDGEdge,
    CDGEdgeType,
    CryptoAlgorithmNode,
    CryptoLibraryNode,
    MigrationPlan,
    MigrationPriority,
    NistQuantumVulnClass,
    PQCAlgorithmId,
    PQCAlgorithmNode,
    NistSecurityLevel,
    compute_urgency_score,
)
from cryptodep.schema.pqc_lookup import (
    PQC_MIGRATION_TABLE,
    QUANTUM_VULNERABLE_FAMILIES,
    QUANTUM_SAFE_SYMMETRIC_FAMILIES,
    NIST_PQC_FAMILIES,
    GROVER_WEAKENED_FAMILIES,
)
from cryptodep.state import CDGState, CryptoFinding
from cryptodep.tools.ast_tools import EXT_LANG, source_ref_path

log = structlog.get_logger().bind(agent_name="A4:CDGBuilder")

# Canonical PQCAlgorithmNode definitions keyed by PQCAlgorithmId
_PQC_NODE_CATALOG: Dict[PQCAlgorithmId, PQCAlgorithmNode] = {
    PQCAlgorithmId.ML_KEM_768: PQCAlgorithmNode(
        node_id=f"cdg:node:pqc:{PQCAlgorithmId.ML_KEM_768.value}",
        label="ML-KEM-768",
        algorithm_id=PQCAlgorithmId.ML_KEM_768,
        fips_standard="FIPS 203",
        security_level=NistSecurityLevel.L3,
        primitive_type="KEM",
        math_basis="lattice_mlwe",
        replaces=["RSA", "ECDH", "DH", "ECC"],
    ),
    PQCAlgorithmId.ML_DSA_65: PQCAlgorithmNode(
        node_id=f"cdg:node:pqc:{PQCAlgorithmId.ML_DSA_65.value}",
        label="ML-DSA-65",
        algorithm_id=PQCAlgorithmId.ML_DSA_65,
        fips_standard="FIPS 204",
        security_level=NistSecurityLevel.L3,
        primitive_type="DSA",
        math_basis="lattice_mlwe",
        replaces=["ECDSA", "DSA"],
    ),
}


# algorithm_families that represent import noise, not actual crypto usage
_NOISE_FAMILIES: frozenset[str] = frozenset({
    "CRYPTO_IMPORT", "TLS", "UNKNOWN",
    # Secure PRNGs — not classical algorithms needing PQC migration
    "SecureRandom", "Random", "RNG-default",
    # Encoding schemes — not crypto algorithms
    "Base64", "BASE64", "URL-safe",
    # Overly generic catch-all values from Semgrep rules
    "other",
    # Compound signature schemes (SHA256withRSA, etc.) — the underlying key
    # algorithm (RSA, ECC) is captured separately via direct key-generation findings
    "SHA256withRSA", "SHA1withRSA", "SHA384withRSA", "SHA512withRSA",
    "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA",
})

# Parameter values that represent raw key sizes (e.g. "256 bits", "128-bit").
# These are bit-count annotations, not algorithm identifiers.
_BITSIZE_PARAM_RE = re.compile(r'^\d+[\s\-]bits?$', re.IGNORECASE)

# Regex to extract common asymmetric key sizes from compound labels/params.
# Used in _dedup_by_family to recover "RSA-2048" from "SHA256 + RSA 2048-bit" etc.
_KEY_SIZE_RE = re.compile(r'\b(1024|2048|3072|4096)\b')

# Confidence assigned to import-graph stub edges (deterministic, lower than A3 LLM edges).
# Also used as the exclusion threshold in _synthesize_component_library_edges to prevent
# noise-only classes (no A3 LLM edge) from becoming AppComponent nodes.
_IMPORT_GRAPH_STUB_CONFIDENCE: float = 0.75

# Known crypto library import prefixes — used to reject non-crypto imports like java.util
_CRYPTO_LIB_PREFIXES: tuple[str, ...] = (
    "java.security", "javax.crypto", "javax.net.ssl",
    "org.bouncycastle", "com.nimbusds", "org.spongycastle",
    "io.jsonwebtoken", "org.jose4j", "org.jasypt",
    "org.apache.commons.crypto", "org.conscrypt",
    "org.springframework.util.DigestUtils",
    "com.google.crypto", "dev.paseto",
    # Python Crypto Libs
    "hashlib", "cryptography", "jwt", "pycryptodome", "passlib", "hmac",
    "crypto", "node:crypto", "webcrypto",
)


def _findings_to_algo_nodes(
    findings: List[CryptoFinding],
) -> Dict[str, CryptoAlgorithmNode]:
    """Deduplicate findings into CryptoAlgorithmNodes keyed by node_id.

    Deduplication key: (algorithm_family, parameter_set).
    Multiple findings with the same key are merged — the first finding's
    source_ref is kept as primary.

    Returns:
        Dict mapping node_id → CryptoAlgorithmNode.
    """
    seen: Dict[Tuple[str, Optional[str]], CryptoAlgorithmNode] = {}
    for f in findings:
        family = f["algorithm_family"]
        if family in _NOISE_FAMILIES:
            continue
        param = f.get("parameter_set")
        # Skip findings whose parameter is a raw bit-size notation (e.g. "256 bits", "128-bit").
        # Only filter pure bit-count params; keep compound names like "SHA-256" or "AES-256-GCM".
        if param and _BITSIZE_PARAM_RE.match(param.strip()):
            continue
        key = (family, param)
        if key in seen:
            continue

        vuln_class = _classify_vuln(family)

        # Q3: Grover weakening — apply only to symmetric families with undersized keys.
        if vuln_class == NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC and param:
            m = re.search(r"(\d+)", param)
            if m:
                key_bits = int(m.group(1))
                if key_bits < 256 and family.upper() in {f.upper() for f in GROVER_WEAKENED_FAMILIES}:
                    vuln_class = NistQuantumVulnClass.GROVER_WEAKENED

        priority = (
            MigrationPriority.CRITICAL if vuln_class == NistQuantumVulnClass.QUANTUM_VULNERABLE
            else MigrationPriority.HIGH if vuln_class == NistQuantumVulnClass.GROVER_WEAKENED
            else MigrationPriority.NOT_REQUIRED
        )
        # Determine canonical label: prefer explicit parameter_set when present
        # Keep parameter_set as-is (param) to avoid breaking ground-truth case-sensitivity.
        # Rules:
        # - If param contains '-' or '/', treat it as a compound name and use as-is (trim quotes).
        # - If param is purely numeric, join with family (e.g., RSA + 2048 -> RSA-2048).
        # - If param looks like an alphanumeric JWT alg (letters+digits, e.g., HS256), use as-is.
        # - Otherwise, default to family-param to preserve meaning.
        if param:
            p = param.strip().strip('\"\'')
            if ('-' in p) or ('/' in p):
                label = p
            elif p.isdigit():
                label = f"{family}-{p}"
            elif any(c.isalpha() for c in p) and any(c.isdigit() for c in p):
                # e.g., HS256, RS256
                label = p
            else:
                label = f"{family}-{p}"
        else:
            label = family

        node = CryptoAlgorithmNode(
            label=label,
            algorithm_family=family,
            parameter_set=param,
            use_context=f.get("use_context"),
            source_ref=f.get("source_ref"),
            confidence=f.get("confidence", 1.0),
            quantum_vuln_class=vuln_class,
            migration_priority=priority,
            hndl_risk=(vuln_class in {
                NistQuantumVulnClass.QUANTUM_VULNERABLE,
                NistQuantumVulnClass.GROVER_WEAKENED,
            }),
        )
        seen[key] = node

    return {n.node_id: n for n in seen.values()}


# Public alias used by tests
_build_algo_nodes = _findings_to_algo_nodes


def _dedup_by_family(
    algo_nodes: Dict[str, CryptoAlgorithmNode],
) -> Dict[str, CryptoAlgorithmNode]:
    """Merge CryptoAlgorithmNodes that share the same algorithm_family.

    When Semgrep fires multiple rules for the same underlying algorithm
    (e.g., KeyPairGenerator("RSA"), Signature("SHA256withRSA"), JWT "RS256"),
    each produces a separate finding with the same family but different
    parameter_set values.  This pass collapses them into one canonical node.

    Selection priority within each family group:
      1. Node whose parameter_set is purely numeric (e.g., "2048") →
         produces the "RSA-2048" label and carries the key-size information.
      2. Node with no parameter_set (bare family label).
      3. Any remaining node (last-resort).

    For quantum-safe families with legitimately distinct size variants
    (e.g., HMAC-256 vs. HMAC-512), each numeric parameter is treated as its
    own canonical node and all are kept.
    """
    family_groups: Dict[str, List[CryptoAlgorithmNode]] = defaultdict(list)
    for node in algo_nodes.values():
        family_groups[node.algorithm_family].append(node)

    result: Dict[str, CryptoAlgorithmNode] = {}
    for family, group in family_groups.items():
        if len(group) == 1:
            n = group[0]
            # Even for single-node groups, normalize compound labels for quantum-vulnerable
            # algorithms (e.g. "SHA256 + RSA 2048-bit" → "RSA-2048").
            if (
                n.quantum_vuln_class == NistQuantumVulnClass.QUANTUM_VULNERABLE
                and n.parameter_set
                and not n.parameter_set.strip().strip("\"'").isdigit()
            ):
                text = (n.label or "") + " " + (n.parameter_set or "")
                m = _KEY_SIZE_RE.search(text)
                if m:
                    size = int(m.group(1))
                    n = n.model_copy(update={
                        "parameter_set": str(size),
                        "label": f"{n.algorithm_family}-{size}",
                    })
            result[n.node_id] = n
            continue

        vuln = group[0].quantum_vuln_class

        numeric = [
            n for n in group
            if n.parameter_set and n.parameter_set.strip().strip("\"'").isdigit()
        ]

        if vuln == NistQuantumVulnClass.QUANTUM_VULNERABLE:
            # Quantum-vulnerable families (RSA, ECC, DH): one canonical node.
            # Pick the node with the largest numeric key-size param.
            # Guard: 65537 is a public exponent, not a key size.
            def _is_key_size(p: Optional[str]) -> bool:
                if not p: return False
                s = p.strip().strip("\"'")
                return s.isdigit() and s != "65537"

            numeric = [n for n in group if _is_key_size(n.parameter_set)]
            if numeric:
                best = max(numeric, key=lambda n: int(n.parameter_set.strip().strip("\"'")))
            else:
                # No purely-numeric param found.  Try to extract key size from
                # compound labels/params (e.g. "SHA256 + RSA 2048-bit" → 2048).
                with_keysize = []
                for n in group:
                    text = (n.label or "") + " " + (n.parameter_set or "")
                    m = _KEY_SIZE_RE.search(text)
                    if m:
                        with_keysize.append((n, int(m.group(1))))
                if with_keysize:
                    best_n, best_size = max(with_keysize, key=lambda t: t[1])
                    best = best_n.model_copy(update={
                        "parameter_set": str(best_size),
                        "label": f"{best_n.algorithm_family}-{best_size}",
                    })
                else:
                    no_param = [n for n in group if n.parameter_set is None]
                    best = no_param[0] if no_param else group[0]
            result[best.node_id] = best
            log.debug(
                "a4_dedup_family",
                family=family,
                kept=best.label,
                discarded=[n.label for n in group if n.node_id != best.node_id],
            )
        else:
            # Quantum-safe: keep numeric-size variants separately + no-param variant.
            kept_nodes = list(numeric) + [n for n in group if n.parameter_set is None]
            if not kept_nodes:
                kept_nodes = [group[0]]
            for n in kept_nodes:
                result[n.node_id] = n

    return result


def _classify_vuln(algorithm_family: str) -> NistQuantumVulnClass:
    """Map algorithm family string to NIST quantum vulnerability class.

    Decision tree (Fig. 4):
      Q2: already a NIST PQC standard → QUANTUM_SAFE_PQC
      Q1: public-key algorithm broken by Shor's → QUANTUM_VULNERABLE
      Q4: symmetric/hash family → QUANTUM_SAFE_SYMMETRIC (key-size Q3 check in caller)
    """
    upper = algorithm_family.upper()

    def _matches(s: str, families: frozenset) -> bool:
        """Delimiter-safe match: exact OR prefix followed by '-' or '_'."""
        for f in families:
            fu = f.upper()
            if s == fu or s.startswith(fu + "-") or s.startswith(fu + "_"):
                return True
        return False

    # Q2: already a NIST PQC standard → target state, no migration needed
    if _matches(upper, NIST_PQC_FAMILIES):
        return NistQuantumVulnClass.QUANTUM_SAFE_PQC
    # Q1: public-key algorithm broken by Shor's → immediate replacement required
    if _matches(upper, QUANTUM_VULNERABLE_FAMILIES):
        return NistQuantumVulnClass.QUANTUM_VULNERABLE
    # Q4: symmetric/hash family → safe or grover-weakened (key-size check in caller)
    if _matches(upper, QUANTUM_SAFE_SYMMETRIC_FAMILIES):
        return NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC
    return NistQuantumVulnClass.UNKNOWN


def _build_pqc_nodes(
    algo_nodes: Dict[str, CryptoAlgorithmNode],
) -> Tuple[List[PQCAlgorithmNode], List[CDGEdge]]:
    """Create PQCAlgorithmNodes and MIGRATES_TO edges for quantum_vulnerable algos.

    PQC nodes are deduplicated by algorithm_id — multiple classical algorithms
    mapping to ML-KEM-768 produce only one PQC node.

    Returns:
        (list of unique PQCAlgorithmNodes, list of MIGRATES_TO CDGEdges)
    """
    pqc_nodes: Dict[PQCAlgorithmId, PQCAlgorithmNode] = {}
    migrates_edges: List[CDGEdge] = []

    for node_id, algo_node in algo_nodes.items():
        if algo_node.quantum_vuln_class != NistQuantumVulnClass.QUANTUM_VULNERABLE:
            continue
        mapping = PQC_MIGRATION_TABLE.get(algo_node.algorithm_family)
        if mapping is None:
            log.warning("a4_no_pqc_mapping", family=algo_node.algorithm_family)
            continue

        # Always iterate ALL available contexts so dual-use algorithms (RSA, ECC) get
        # both replacements — e.g., RSA-2048 → ML-KEM-768 (KEM) AND ML-DSA-65 (signing).
        # use_context from A2 detection is intentionally ignored here: a single detected
        # use (e.g., key_exchange) does not preclude the other use being present in the
        # same codebase. The migration roadmap must cover all PQC substitutions.
        context_keys: List[str] = [k for k in ("key_exchange", "digital_signature") if mapping.get(k)]

        for ctx in context_keys:
            sub = mapping.get(ctx)
            if sub is None:
                continue
            pqc_algo_id: PQCAlgorithmId = sub["replacement"]
            if pqc_algo_id not in pqc_nodes:
                pqc_node = _PQC_NODE_CATALOG.get(pqc_algo_id)
                if pqc_node is None:
                    log.warning("a4_pqc_catalog_miss", algo_id=pqc_algo_id)
                    continue
                pqc_nodes[pqc_algo_id] = pqc_node

            pqc_node_id = pqc_nodes[pqc_algo_id].node_id
            migrates_edges.append(CDGEdge(
                edge_type=CDGEdgeType.MIGRATES_TO,
                source_id=node_id,
                target_id=pqc_node_id,
                confidence=1.0,
                evidence=mapping["rationale"],
            ))

    return list(pqc_nodes.values()), migrates_edges


def _is_test_file(file_path: str) -> bool:
    """Return True if file_path is a test or integration-test source file.

    Matches standard Maven/Gradle test directories (/test/, /it/) and
    conventional Java test file suffixes (Test.java, IT.java, *IntegrationTest.java).
    """
    p = file_path.replace("\\", "/")
    if "/test/" in p or "/it/" in p:
        return True
    basename = os.path.basename(p)
    return (
        basename.endswith("Test.java")
        or basename.endswith("Tests.java")
        or basename.endswith("IT.java")
        or basename.endswith("IntegrationTest.java")
        or basename.endswith("_test.py")
        or basename.endswith("_spec.py")
    )


def _extract_class_name(source_ref: str) -> str:
    """Extract class/module name from a source_ref file path.

    Examples:
        'src/main/java/.../CryptoUtil.java:L42'  -> 'CryptoUtil'
        'src/auth/jwt_service.py:42'             -> 'jwt_service'
        'CryptoUtil.java'                        -> 'CryptoUtil'
        'test_repos/pygoat/introduction/views.py' -> 'views'
    """
    path = source_ref_path(source_ref).replace("\\", "/")
    # For both Java and Python, use simple file stem as label
    # This matches ground truth conventions (CryptoUtil, views, utility)
    return os.path.splitext(os.path.basename(path))[0]



# Java stdlib crypto packages where sub-packages are truncated to the root.
# (e.g., java.security.interfaces → java.security, javax.crypto.spec → javax.crypto)
# Third-party library sub-packages (org.jose4j.jws, io.jsonwebtoken.io) are kept as-is.
_JAVA_STDLIB_CRYPTO_ROOTS: dict[str, int] = {
    "java.security": 2,
    "javax.crypto": 2,
    "javax.net.ssl": 3,
}

# Canonical library names used as node labels in the CDG.
# The import-graph augmentation only creates edges for imports that normalize
# to one of these canonical names, preventing sub-package proliferation.
_CANONICAL_CRYPTO_LIBS: frozenset[str] = frozenset({
    # Java
    "java.security", "javax.crypto", "javax.net.ssl",
    "io.jsonwebtoken",
    "org.jose4j.jws",  # jwe and jwk are redirected → jws by _canonicalize_lib_import
    "org.bouncycastle.jce", "org.bouncycastle.crypto",
    "com.nimbusds.jose", "com.nimbusds.jwt",
    "org.jasypt.encryption",
    "org.apache.commons.crypto",
    "org.springframework.util.DigestUtils",
    "com.google.crypto.tink",
    # Python
    "hashlib", "cryptography", "jwt", "hmac", "passlib",
    "node:crypto", "webcrypto",
})


def _normalize_lib_name(ref: str) -> str:
    """Normalize a class-level Java/Python ref to its canonical package label.

    A3 produces fully-qualified targets like 'java.security.KeyPair' or
    'io.jsonwebtoken.SignatureAlgorithm.RS256'. The evaluation ground truth
    uses package-level labels ('java.security', 'io.jsonwebtoken').

    Strategy:
      1. Find the first dot-separated component that starts with an uppercase
         letter (a class name) and keep only the package prefix before it.
      2. If no uppercase component, check if the ref is a known sub-package
         and truncate to the canonical root depth.

    Examples:
        'java.security.KeyPair'                -> 'java.security'
        'java.security.interfaces.RSAPublicKey'-> 'java.security'
        'io.jsonwebtoken.SignatureAlgorithm'   -> 'io.jsonwebtoken'
        'java.security.interfaces'             -> 'java.security'
        'java.security'                        -> 'java.security'  (unchanged)
        'javax.crypto'                         -> 'javax.crypto'   (unchanged)
    """
    if ref == "crypto" or ref.startswith("crypto."):
        return "node:crypto"
    if ref == "org.springframework.util.DigestUtils":
        return ref
    if ref == "node:crypto" or ref.startswith("node:crypto."):
        return "node:crypto"
    parts = ref.split(".")
    pkg_end = len(parts)  # index of first uppercase component (class name start)
    for i, part in enumerate(parts):
        if part and part[0].isupper():
            if i == 0:
                return ref  # no package prefix — leave unchanged
            pkg_end = i
            break

    pkg = ".".join(parts[:pkg_end])
    # Always apply stdlib root truncation on the package portion (strips sub-packages
    # like 'java.security.interfaces' that result from stripping a class name).
    for root, depth in _JAVA_STDLIB_CRYPTO_ROOTS.items():
        if pkg == root or pkg.startswith(root + "."):
            return ".".join(parts[:depth])
    return pkg


def _is_library_ref(ref: str) -> bool:
    """Heuristic: is ref a crypto library import path (not a local source file)?

    Accepts refs that start with a known crypto library prefix.
    Rejects local source files, non-crypto libraries (java.util, com.fasterxml.jackson…),
    and deep FQNs that are app-internal classes.
    """
    if not ref or ref == "unknown":
        return False
    if "/" in ref or "\\" in ref:
        return False
    if ref.endswith(tuple(EXT_LANG)):
        return False
    # Accept single-word imports if they are in the prefix list (common in Python, e.g., 'hashlib')
    if "." not in ref:
        return any(ref == p for p in _CRYPTO_LIB_PREFIXES)
    # Reject deep FQNs (≥5 dot-separated components) — these are local app classes
    if ref.count(".") >= 5:
        return False
    # Accept only known crypto library prefixes to avoid java.util, com.fasterxml.jackson…
    norm = _normalize_lib_name(ref)
    return any(norm == p or norm.startswith(p + ".") for p in _CRYPTO_LIB_PREFIXES)


def _canonicalize_lib_import(imp: str) -> Optional[str]:
    """Map an import path to its canonical CDG library label, or None if not a crypto lib.

    Uses `_normalize_lib_name()` first to strip class names, then checks that the
    result matches one of the canonical crypto library names in `_CANONICAL_CRYPTO_LIBS`.

    For org.jose4j sub-packages (jwk, keys, jwt.consumer, etc.) that are not in the
    canonical set, they are mapped to the parent `org.jose4j.jws` canonical artifact if
    they belong to the jose4j suite (since JWS is the primary crypto module).
    """
    if not _is_library_ref(imp):
        return None
    norm = _normalize_lib_name(imp)
    if norm in _CANONICAL_CRYPTO_LIBS:
        return norm
    # Consolidate org.jose4j.* sub-packages to the canonical JWS module
    if norm.startswith("org.jose4j.") and norm != "org.jose4j.jws":
        return "org.jose4j.jws"
    # Consolidate io.jsonwebtoken sub-packages
    if norm.startswith("io.jsonwebtoken.") and norm != "io.jsonwebtoken":
        return "io.jsonwebtoken"
    # Consolidate Python hashlib.* sub-modules to root hashlib
    if norm.startswith("hashlib."):
        return "hashlib"
    # Consolidate Python cryptography.* sub-modules
    if norm.startswith("cryptography."):
        return "cryptography"
    return None


def _augment_edges_from_import_graph(
    validated_edges: List[CDGEdge],
    import_graph: dict,
    files_with_real_findings: Optional[Set[str]] = None,
) -> List[CDGEdge]:
    """Supplement A3 validated_edges with deterministic import-graph–based edges.

    A1 builds import_graph = {file_path: [import_path, ...]} from actual source
    imports. A3 may miss some of these in its LLM reasoning. This function creates
    CDGEdge stubs (confidence=0.75) for file→library pairs found in the import_graph
    that are not already covered by validated_edges.

    Only imports that map to canonical crypto library names are included to
    avoid sub-package proliferation.

    Args:
        validated_edges: existing CDGEdge list from A3.
        import_graph: mapping of file_path → [import_string, ...] from A1.
        files_with_real_findings: when provided, only files in this set are
            augmented. Files absent from this set (noise-only: CRYPTO_IMPORT,
            TLS) are skipped to prevent false-positive CDG edges.
    """
    existing: set = set()
    for edge in validated_edges:
        src = source_ref_path(edge.source_id)
        canonical = _canonicalize_lib_import(edge.target_id)
        if canonical:
            existing.add((src, canonical))

    extra: List[CDGEdge] = []
    for file_path, imports in import_graph.items():
        if _is_test_file(file_path):
            continue
        # Skip files with no non-noise A2 findings (prevents FP augmentation edges)
        if files_with_real_findings is not None and file_path not in files_with_real_findings:
            continue
        if not isinstance(imports, (list, tuple)):
            continue
        for imp in imports:
            if not isinstance(imp, str):
                continue
            canonical = _canonicalize_lib_import(imp)
            if canonical is None:
                continue
            key = (file_path, canonical)
            if key not in existing:
                existing.add(key)
                extra.append(CDGEdge(
                    edge_type=CDGEdgeType.USES,  # placeholder; synthesize() uses target_id
                    source_id=file_path,
                    target_id=canonical,
                    confidence=_IMPORT_GRAPH_STUB_CONFIDENCE,
                    evidence=f"import-graph: {file_path} imports {canonical}",
                ))
    return validated_edges + extra


def _synthesize_component_library_edges(
    findings: List[CryptoFinding],
    validated_edges: List[CDGEdge],
    algo_nodes: Dict[str, "CryptoAlgorithmNode"],
) -> Tuple[List[AppComponentNode], List[CryptoLibraryNode], List[CDGEdge]]:
    """Synthesize AppComponent and CryptoLibrary nodes from findings + A3 edges.

    A3 produces edges with source_id = source_ref (file path) and
    target_id = library import path.  This function:
      1. Creates an AppComponentNode for each unique class/module in findings.
      2. Creates a CryptoLibraryNode for each unique library in A3 edges.
      3. Builds 'uses' edges:    AppComponent  → CryptoLibrary
      4. Builds 'implements' edges: CryptoLibrary → CryptoAlgorithm

    Returns:
        (app_nodes, lib_nodes, new_edges) — all with proper CDGNode UUIDs.
    """
    # ── 1. AppComponent nodes: one per unique class from findings ─────────────
    # Only create an AppComponent if the class has at least one non-noise finding.
    # This prevents SecureRandom-only classes (e.g., DOMCrossSiteScripting) from
    # polluting the CDG with false-positive AppComponent nodes.
    class_to_app: Dict[str, AppComponentNode] = {}
    file_to_class: Dict[str, str] = {}  # normalized file path → class name

    # First pass: identify classes that have at least one non-noise finding
    # OR appear as source files with edges to known crypto libraries (from A3).
    # The A3 source includes classes like JWTHeaderJKUEndpoint whose imports are
    # flagged as CRYPTO_IMPORT (noise family) but genuinely use crypto libraries.
    _classes_with_real_crypto: set = set()
    for f in findings:
        if f.get("algorithm_family") in _NOISE_FAMILIES:
            continue
        src = f.get("source_ref", "")
        if not src:
            continue
        class_name = _extract_class_name(src)
        if class_name:
            _classes_with_real_crypto.add(class_name)
    # Also include classes that have HIGH-confidence A3 edges to known crypto library prefixes.
    # Exclude import_graph stubs to prevent noise-only classes
    # (e.g. DOMCrossSiteScripting with only SecureRandom imports) from becoming AppComponents.
    for edge in validated_edges:
        if edge.confidence <= _IMPORT_GRAPH_STUB_CONFIDENCE:
            continue
        tgt = edge.target_id
        if not _is_library_ref(tgt):
            continue
        src_file = source_ref_path(edge.source_id)
        if not _is_test_file(src_file):
            class_name = _extract_class_name(src_file)
            if class_name:
                _classes_with_real_crypto.add(class_name)

    for f in findings:
        src = f.get("source_ref", "")
        if not src:
            continue
        file_path = source_ref_path(src)
        class_name = _extract_class_name(src)
        if not class_name:
            continue
        file_to_class[file_path] = class_name
        if (class_name not in class_to_app
                and not _is_test_file(file_path)
                and class_name in _classes_with_real_crypto):
            ext = os.path.splitext(file_path)[-1].lower()
            lang = EXT_LANG.get(ext, "unknown")
            class_to_app[class_name] = AppComponentNode(
                label=class_name,
                component_type="class",
                language=lang,
                file_path=file_path,
                owns_crypto=True,
            )

    # ── 2. CryptoLibrary nodes: from A3 edge target_ids that look like imports ─
    lib_name_to_node: Dict[str, CryptoLibraryNode] = {}
    # file path → set of library names used by that file
    file_to_libs: Dict[str, Set[str]] = defaultdict(set)

    for edge in validated_edges:
        tgt = edge.target_id
        src_file = source_ref_path(edge.source_id)

        # Canonicalize library ref (e.g., hashlib.md5 -> hashlib)
        canonical_tgt = _canonicalize_lib_import(tgt)
        if canonical_tgt is None:
            continue

        file_to_libs[src_file].add(canonical_tgt)

        if canonical_tgt not in lib_name_to_node:
            is_java = canonical_tgt.startswith(("java.", "javax.", "org.", "com.", "net."))
            is_python = canonical_tgt in ("hashlib", "cryptography", "jwt", "hmac", "passlib")
            is_javascript = canonical_tgt in ("node:crypto", "webcrypto")
            lib_name_to_node[canonical_tgt] = CryptoLibraryNode(
                label=canonical_tgt,
                library_name=canonical_tgt,
                language="java" if is_java else ("python" if is_python else ("javascript" if is_javascript else "unknown")),
                import_path=canonical_tgt,
            )

    # ── 3. 'uses' edges: AppComponent → CryptoLibrary ────────────────────────
    new_edges: List[CDGEdge] = []
    uses_seen: Set[Tuple[str, str]] = set()

    for edge in validated_edges:
        src_file = source_ref_path(edge.source_id)
        canonical_tgt = _canonicalize_lib_import(edge.target_id)
        class_name = file_to_class.get(src_file)

        if not class_name or class_name not in class_to_app:
            continue
        if canonical_tgt is None or canonical_tgt not in lib_name_to_node:
            continue

        app_id = class_to_app[class_name].node_id
        lib_id = lib_name_to_node[canonical_tgt].node_id
        key = (app_id, lib_id)
        if key not in uses_seen:
            uses_seen.add(key)
            new_edges.append(CDGEdge(
                edge_type=CDGEdgeType.USES,
                source_id=app_id,
                target_id=lib_id,
                confidence=edge.confidence,
                evidence=edge.evidence,
            ))

    # ── 4. 'implements' edges: CryptoLibrary → CryptoAlgorithm ───────────────
    # Inference: if class C uses library L, and C's file contains algorithm A,
    # then L implements A.
    impl_seen: Set[Tuple[str, str]] = set()

    for f in findings:
        src = f.get("source_ref", "")
        src_file = source_ref_path(src)
        libs = file_to_libs.get(src_file, set())
        if not libs:
            continue

        # Find matching algo node (prefer exact parameter_set match)
        family = f["algorithm_family"]
        param = f.get("parameter_set")
        matching_algo: Optional["CryptoAlgorithmNode"] = None
        for n in algo_nodes.values():
            if n.algorithm_family == family:
                if n.parameter_set == param:
                    matching_algo = n
                    break
                if matching_algo is None:
                    matching_algo = n  # family-level fallback

        if matching_algo is None:
            continue

        for lib_name in libs:
            if lib_name not in lib_name_to_node:
                continue
            lib_id = lib_name_to_node[lib_name].node_id
            algo_id = matching_algo.node_id
            key = (lib_id, algo_id)
            if key not in impl_seen:
                impl_seen.add(key)
                new_edges.append(CDGEdge(
                    edge_type=CDGEdgeType.IMPLEMENTS,
                    source_id=lib_id,
                    target_id=algo_id,
                    confidence=1.0,
                    evidence=f"{lib_name} provides {matching_algo.label}",
                ))

    # ── 5. Infer 'uses' edges: AppComponent → CryptoLibrary via findings ─────────
    # When A3 validated_edges originate from test files (not main source files),
    # the USES edges above only cover test AppComponents. This pass infers USES
    # edges for main-source AppComponents: if AppComponent C has findings for
    # algorithm A, and CryptoLibrary L implements A, then C uses L.
    algo_id_to_lib_ids: Dict[str, List[str]] = defaultdict(list)
    for edge in new_edges:
        if edge.edge_type == CDGEdgeType.IMPLEMENTS:
            algo_id_to_lib_ids[edge.target_id].append(edge.source_id)

    for f in findings:
        src = f.get("source_ref", "")
        src_file = source_ref_path(src)
        class_name = file_to_class.get(src_file)
        if not class_name or class_name not in class_to_app:
            continue
        app_id = class_to_app[class_name].node_id

        family = f["algorithm_family"]
        param = f.get("parameter_set")
        for n in algo_nodes.values():
            if n.algorithm_family != family:
                continue
            if param and n.parameter_set and n.parameter_set != param:
                continue
            for lib_id in algo_id_to_lib_ids.get(n.node_id, []):
                key = (app_id, lib_id)
                if key not in uses_seen:
                    uses_seen.add(key)
                    new_edges.append(CDGEdge(
                        edge_type=CDGEdgeType.USES,
                        source_id=app_id,
                        target_id=lib_id,
                        confidence=0.85,
                        evidence=f"inferred: {class_name} uses {family} provided by library",
                    ))
            break  # matched algorithm; no need to keep scanning

    # ── 6. Back-fill implements edges for inferred USES paths ────────────────
    # Step 5 created USES edges for AppComponents that had no validated A3 edge
    # (e.g. DisplayUser → java.security via SHA-256 inference). Step 4 missed
    # these because file_to_libs was built before inference. This pass creates
    # the corresponding CryptoLibrary → CryptoAlgorithm implements edges by
    # looking at each inferred USES edge and the findings for that AppComponent.
    # Collect step-5 inferred USES edges (confidence=0.85) to back-fill implements
    inferred_app_to_libs_low: Dict[str, List[str]] = defaultdict(list)
    for edge in new_edges:
        if edge.edge_type == CDGEdgeType.USES and 0.80 <= edge.confidence < 0.90:
            inferred_app_to_libs_low[edge.source_id].append(edge.target_id)

    # Build reverse: lib_node_id → lib_name
    lib_id_to_name: Dict[str, str] = {n.node_id: name for name, n in lib_name_to_node.items()}
    # Build app_node_id → file_path
    app_id_to_file: Dict[str, str] = {
        class_to_app[cls].node_id: fpath
        for fpath, cls in file_to_class.items()
        if cls in class_to_app
    }

    for app_id, lib_ids in inferred_app_to_libs_low.items():
        app_file = app_id_to_file.get(app_id)
        if not app_file:
            continue
        for f in findings:
            src_file = source_ref_path(f.get("source_ref", ""))
            if src_file != app_file:
                continue
            family = f["algorithm_family"]
            if family in _NOISE_FAMILIES:
                continue
            param = f.get("parameter_set")
            if param and _BITSIZE_PARAM_RE.match(param.strip()):
                continue
            for n in algo_nodes.values():
                if n.algorithm_family != family:
                    continue
                if param and n.parameter_set and n.parameter_set != param:
                    continue
                for lib_id in lib_ids:
                    key = (lib_id, n.node_id)
                    if key not in impl_seen:
                        impl_seen.add(key)
                        lib_name = lib_id_to_name.get(lib_id, lib_id)
                        new_edges.append(CDGEdge(
                            edge_type=CDGEdgeType.IMPLEMENTS,
                            source_id=lib_id,
                            target_id=n.node_id,
                            confidence=0.85,
                            evidence=f"{lib_name} provides {n.label} (inferred via AppComponent)",
                        ))
                break

    return list(class_to_app.values()), list(lib_name_to_node.values()), new_edges


def _compute_centrality(
    node_ids: List[str],
    edges: List[CDGEdge],
) -> Dict[str, float]:
    """Compute betweenness centrality for CDG nodes using networkx.

    Returns dict mapping node_id → normalized betweenness centrality [0.0, 1.0].
    Nodes not reachable (isolated) receive 0.0.
    """
    G = nx.DiGraph()
    G.add_nodes_from(node_ids)
    for edge in edges:
        G.add_edge(edge.source_id, edge.target_id)

    raw = nx.betweenness_centrality(G, normalized=True)
    return {nid: round(raw.get(nid, 0.0), 4) for nid in node_ids}


def _recompute_urgency(
    algo_node: CryptoAlgorithmNode,
    centrality_score: float,
    data_lifetime_years: float = 7.0,
) -> CryptoAlgorithmNode:
    """Return a copy of algo_node with migration_urgency_score updated.

    Quantum-vulnerable nodes always use "critical" criticality so that even
    isolated nodes (G=0) receive a meaningful non-zero score (e.g. RSA-2048
    with D=0.8 and HNDL bonus → 90).  GROVER_WEAKENED nodes use "high"
    criticality and pass algo_family + key_size to activate the Gv term.
    Safe nodes default to "medium".
    """
    if algo_node.quantum_vuln_class == NistQuantumVulnClass.QUANTUM_VULNERABLE:
        criticality = "critical"
    elif algo_node.quantum_vuln_class == NistQuantumVulnClass.GROVER_WEAKENED:
        criticality = "high"
    else:
        criticality = "medium"
    score = compute_urgency_score(
        vuln_class=algo_node.quantum_vuln_class,
        business_criticality=criticality,
        data_lifetime_years=data_lifetime_years,
        graph_centrality=centrality_score,
        hndl_risk=algo_node.hndl_risk,
        algo_family=algo_node.algorithm_family or "",
        key_size=algo_node.key_size_bits or 0,
    )
    return algo_node.model_copy(update={"migration_urgency_score": score})


def _build_cdg_document(
    node_dicts: List[dict],
    edges: List[CDGEdge],
    migration_plan: MigrationPlan,
    repo_path: str,
    run_id: str,
    a3_proposed_edges: int = 0,
    a3_validated_edges: int = 0,
) -> CDGDocument:
    """Assemble and Pydantic-validate the complete CDGDocument (AC-A4-01)."""
    a3_hallucination_rate = (
        round((a3_proposed_edges - a3_validated_edges) / a3_proposed_edges, 4)
        if a3_proposed_edges > 0
        else 0.0
    )
    return CDGDocument(
        target_repo={"path": repo_path},
        scan_stats={
            "run_id": run_id,
            "node_count": len(node_dicts),
            "edge_count": len(edges),
            "a3_proposed_edges": a3_proposed_edges,
            "a3_validated_edges": a3_validated_edges,
            "a3_hallucination_rate": a3_hallucination_rate,
        },
        nodes=node_dicts,
        edges=edges,
        migration_plan=migration_plan,
    )


def _upsert_node_dict(driver: Any, node_dict: dict) -> None:
    """Reconstruct a typed CDGNode from its dict and upsert to Neo4j."""
    from cryptodep.tools.neo4j_tools import upsert_node
    from cryptodep.schema.cdg_models import CDGNodeType

    node_type_str = node_dict.get("node_type", "")
    try:
        node_type = CDGNodeType(node_type_str)
    except ValueError:
        return

    type_map = {
        CDGNodeType.CRYPTO_ALGORITHM: CryptoAlgorithmNode,
        CDGNodeType.PQC_ALGORITHM: PQCAlgorithmNode,
    }
    cls = type_map.get(node_type)
    if cls is None:
        return
    node = cls.model_validate(node_dict)
    upsert_node(driver, node)


class CDGBuilderAgent(BaseAgent):
    agent_name = "A4:CDGBuilder"

    async def run(self, state: CDGState) -> CDGState:
        t0 = time.time()
        findings: List[CryptoFinding] = state.get("validated_findings", [])
        validated_edges: List[CDGEdge] = state.get("validated_edges", [])
        errors = list(state.get("errors", []))
        # Snapshot A3 counts before validated_edges is augmented by import_graph pass
        _a3_proposed_count = len(state.get("candidate_edges", []))
        _a3_validated_count = len(validated_edges)

        self.log.info("a4_start", finding_count=len(findings), edge_count=len(validated_edges))

        # ── 1. Build + deduplicate CryptoAlgorithmNodes ──────────────────────
        algo_nodes = _findings_to_algo_nodes(findings)
        algo_nodes = _dedup_by_family(algo_nodes)
        self.log.info("a4_algo_nodes", count=len(algo_nodes))

        # ── 2. Add PQC nodes + MIGRATES_TO edges ─────────────────────────────
        pqc_nodes, migrates_edges = _build_pqc_nodes(algo_nodes)
        self.log.info("a4_pqc_nodes", count=len(pqc_nodes), migrates_edges=len(migrates_edges))

        # ── 3. Compute betweenness centrality ─────────────────────────────────
        # NOTE: centrality is computed here using A3-validated edges BEFORE the
        # import-graph augmentation pass (step 4c). This means augmented stub edges
        # (confidence=0.75) do not influence centrality scores. Consequence: centrality
        # and urgency scores may be slightly underestimated for classes whose only CDG
        # edge is import-graph-derived. Fixing this would require moving step 4c before
        # step 3, which changes A5 urgency ranking. Deferred to Phase 2 evaluation.
        all_node_ids = list(algo_nodes.keys()) + [n.node_id for n in pqc_nodes]
        all_edges_for_centrality = validated_edges + migrates_edges
        centrality = _compute_centrality(all_node_ids, all_edges_for_centrality)

        # ── 4. Recompute urgency scores with centrality ───────────────────────
        updated_algo_nodes: Dict[str, CryptoAlgorithmNode] = {}
        for nid, node in algo_nodes.items():
            updated = _recompute_urgency(node, centrality.get(nid, 0.0))
            updated_algo_nodes[nid] = updated

        # ── 4b. Enrich nodes with reachability metadata (from A6, if present) ──
        reachability_map: Dict[str, float] = state.get("reachability_map", {})
        reachability_paths: Dict[str, list] = state.get("reachability_paths", {})
        if reachability_map:
            for nid, node in updated_algo_nodes.items():
                ref = node.source_ref
                if ref and ref in reachability_map:
                    node.metadata["reachability_score"] = reachability_map[ref]
                    node.metadata["entry_point_paths"] = reachability_paths.get(ref, [])

        # ── 4c. Augment validated_edges with deterministic import-graph edges ──
        # A3's LLM-based reasoning can miss crypto library imports between runs.
        # Only augment files that have at least one non-noise finding to prevent
        # CRYPTO_IMPORT/TLS noise-only files from generating false-positive CDG edges.
        import_graph: dict = state.get("import_graph", {})
        if import_graph:
            files_with_real_findings = {
                source_ref_path(f.get("source_ref", ""))
                for f in findings
                if f.get("algorithm_family") not in _NOISE_FAMILIES
                and f.get("source_ref")
            }
            validated_edges = _augment_edges_from_import_graph(
                validated_edges, import_graph, files_with_real_findings
            )

        # ── 5. Synthesize AppComponent + CryptoLibrary nodes and edges ───────
        app_nodes, lib_nodes, component_edges = _synthesize_component_library_edges(
            findings, validated_edges, updated_algo_nodes
        )
        self.log.info(
            "a4_synthesized_nodes",
            app_components=len(app_nodes),
            crypto_libraries=len(lib_nodes),
            component_edges=len(component_edges),
        )

        # ── 6. Assemble CDGDocument ───────────────────────────────────────────
        all_node_dicts = (
            [n.model_dump(mode="python") for n in updated_algo_nodes.values()]
            + [n.model_dump(mode="python") for n in pqc_nodes]
            + [n.model_dump(mode="python") for n in app_nodes]
            + [n.model_dump(mode="python") for n in lib_nodes]
        )
        # Use synthesized component_edges (proper UUIDs) instead of raw A3 edges
        # (which use file paths as source_id and cannot be resolved by eval).
        # Raw validated_edges remain in CDGState for hallucination_rate calculation.
        all_edges = component_edges + migrates_edges
        migration_plan = MigrationPlan(
            total_vulnerable_assets=sum(
                1 for n in updated_algo_nodes.values()
                if n.quantum_vuln_class in {
                    NistQuantumVulnClass.QUANTUM_VULNERABLE,
                    NistQuantumVulnClass.GROVER_WEAKENED,
                }
            )
        )
        cdg_doc = _build_cdg_document(
            node_dicts=all_node_dicts,
            edges=all_edges,
            migration_plan=migration_plan,
            repo_path=state["repo_path"],
            run_id=state["run_id"],
            a3_proposed_edges=_a3_proposed_count,
            a3_validated_edges=_a3_validated_count,
        )

        # ── 6. Persist to SQLite (PRIMARY) ───────────────────────────────────
        db_path = getattr(self.config, "sqlite_db_path", "cdg_store.db")
        from cryptodep.tools.sqlite_tools import get_connection, init_schema, save_cdg
        _conn = get_connection(db_path)
        init_schema(_conn)
        save_cdg(_conn, state["run_id"], cdg_doc, state["repo_path"])
        _conn.close()
        self.log.info("a4_sqlite_saved", path=db_path)

        # ── 7. Persist to Neo4j (best-effort) ────────────────────────────────
        neo4j_stats: Dict[str, int] = {}
        cbom_path = ""
        if self.config.enable_neo4j:
            try:
                import neo4j
                driver = neo4j.GraphDatabase.driver(
                    self.config.neo4j_uri,
                    auth=(self.config.neo4j_user, self.config.neo4j_password),
                    connection_timeout=5,
                    max_connection_lifetime=300,
                )
                from cryptodep.tools.neo4j_tools import (
                    setup_constraints, upsert_edge, count_nodes_and_edges,
                )
                # Verify connection before bulk writes
                with driver.session() as session:
                    session.run("RETURN 1")
                setup_constraints(driver)
                for node_dict in all_node_dicts:
                    _upsert_node_dict(driver, node_dict)
                for edge in all_edges:
                    upsert_edge(driver, edge)
                neo4j_stats = count_nodes_and_edges(driver)
                driver.close()
                self.log.info("a4_neo4j_import", **neo4j_stats)
            except Exception as exc:  # noqa: BLE001
                self.log.warning("a4_neo4j_skip", reason=str(exc)[:120])
                errors.append({
                    "agent": self.agent_name,
                    "error_type": "neo4j_unavailable",
                    "message": str(exc)[:200],
                    "recoverable": True,
                })

        # ── 7. Export CBOM ────────────────────────────────────────────────────
        try:
            from cryptodep.tools.cbom_tools import cdg_to_cbom, export_cbom_json
            cbom = cdg_to_cbom(cdg_doc)
            cbom_path = f"cbom_{state['run_id'][:8]}.json"
            export_cbom_json(cbom, cbom_path)
            self.log.info("a4_cbom_exported", path=cbom_path)
        except Exception as exc:  # noqa: BLE001
            self.log.warning("a4_cbom_skip", reason=str(exc)[:120])
            errors.append({
                "agent": self.agent_name,
                "error_type": "cbom_export_failed",
                "message": str(exc)[:200],
                "recoverable": True,
            })

        elapsed = time.time() - t0
        state.update({
            "cdg_document": cdg_doc,
            "neo4j_import_stats": neo4j_stats,
            "cbom_export_path": cbom_path,
            "sqlite_db_path": db_path,
            "migration_plan": migration_plan,
            "agent_timings": {**state.get("agent_timings", {}), self.agent_name: elapsed},
            "errors": errors,
        })
        self.log.info("a4_complete", nodes=len(all_node_dicts), edges=len(all_edges),
                      elapsed=round(elapsed, 2))
        return state
