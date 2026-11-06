"""
CryptoDep-LLM — CDG Schema v1.0
Python dataclasses + Pydantic models for the Crypto Dependency Graph.

Poltek SSN | Quantum-Ready Cryptography Pillar
NIST refs: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
CBOM baseline: CycloneDX v1.6 / IBM CBOM spec
"""

from __future__ import annotations
from enum import Enum
from typing import Optional, List
from datetime import datetime, timezone
from pydantic import BaseModel, Field, field_validator
import uuid


# ── Enumerations ──────────────────────────────────────────────────────────────

class NistQuantumVulnClass(str, Enum):
    QUANTUM_VULNERABLE      = "quantum_vulnerable"       # RSA, ECC, DH — broken by Shor's
    GROVER_WEAKENED         = "grover_weakened"          # e.g. AES-128 — Grover preimage-halved; key-size upgrade to AES-256 needed
    QUANTUM_SAFE_SYMMETRIC  = "quantum_safe_symmetric"   # AES-256, SHA-3 — Grover-safe at sufficient keylength
    QUANTUM_SAFE_PQC        = "quantum_safe_pqc"         # FIPS 203/204/205 algorithms — target state
    UNKNOWN                 = "unknown"


class NistSecurityLevel(int, Enum):
    L1 = 1  # AES-128 equivalent
    L2 = 2
    L3 = 3  # AES-192 equivalent
    L4 = 4
    L5 = 5  # AES-256 equivalent


class MigrationPriority(str, Enum):
    CRITICAL     = "critical"     # RSA/ECC protecting long-lived secrets (HNDL risk)
    HIGH         = "high"
    MEDIUM       = "medium"
    LOW          = "low"
    NOT_REQUIRED = "not_required"


class PQCAlgorithmId(str, Enum):
    # FIPS 203 — ML-KEM (CRYSTALS-Kyber)
    ML_KEM_512  = "ML-KEM-512"
    ML_KEM_768  = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"
    # FIPS 204 — ML-DSA (CRYSTALS-Dilithium)
    ML_DSA_44   = "ML-DSA-44"
    ML_DSA_65   = "ML-DSA-65"
    ML_DSA_87   = "ML-DSA-87"
    # FIPS 205 — SLH-DSA (SPHINCS+) — 12 parameter sets
    SLH_DSA_SHA2_128S  = "SLH-DSA-SHA2-128s"
    SLH_DSA_SHA2_128F  = "SLH-DSA-SHA2-128f"
    SLH_DSA_SHA2_192S  = "SLH-DSA-SHA2-192s"
    SLH_DSA_SHA2_192F  = "SLH-DSA-SHA2-192f"
    SLH_DSA_SHA2_256S  = "SLH-DSA-SHA2-256s"
    SLH_DSA_SHA2_256F  = "SLH-DSA-SHA2-256f"
    SLH_DSA_SHAKE_128S = "SLH-DSA-SHAKE-128s"
    SLH_DSA_SHAKE_128F = "SLH-DSA-SHAKE-128f"
    SLH_DSA_SHAKE_192S = "SLH-DSA-SHAKE-192s"
    SLH_DSA_SHAKE_192F = "SLH-DSA-SHAKE-192f"
    SLH_DSA_SHAKE_256S = "SLH-DSA-SHAKE-256s"
    SLH_DSA_SHAKE_256F = "SLH-DSA-SHAKE-256f"
    # Draft FIPS 206 — FN-DSA (FALCON)
    FN_DSA_512  = "FN-DSA-512"
    FN_DSA_1024 = "FN-DSA-1024"
    # HQC 2025 — code-based KEM
    HQC_128 = "HQC-128"
    HQC_192 = "HQC-192"
    HQC_256 = "HQC-256"


class CDGEdgeType(str, Enum):
    IMPLEMENTS  = "implements"   # CryptoLibrary → CryptoAlgorithm
    USES        = "uses"         # AppComponent  → CryptoLibrary
    DEPENDS_ON  = "depends_on"   # AppComponent  → AppComponent
    EXPOSES_VIA = "exposes_via"  # BusinessProcess → Protocol
    PROTECTS    = "protects"     # KeyMaterial   → AppComponent / BusinessProcess
    MIGRATES_TO = "migrates_to"  # CryptoAlgorithm → PQCAlgorithm (core CDG novelty)
    RELIES_ON   = "relies_on"    # Protocol → CryptoAlgorithm


class CDGNodeType(str, Enum):
    CRYPTO_ALGORITHM  = "CryptoAlgorithm"
    PQC_ALGORITHM     = "PQCAlgorithm"
    CRYPTO_LIBRARY    = "CryptoLibrary"
    APP_COMPONENT     = "AppComponent"
    PROTOCOL          = "Protocol"
    KEY_MATERIAL      = "KeyMaterial"
    BUSINESS_PROCESS  = "BusinessProcess"


class DetectionMethod(str, Enum):
    LLM_SEMANTIC  = "llm_semantic"
    STATIC_RULE   = "static_rule"
    HYBRID        = "hybrid"
    MANUAL        = "manual"


# ── Base Node ─────────────────────────────────────────────────────────────────

class CDGNodeBase(BaseModel):
    node_id:    str  = Field(default_factory=lambda: f"cdg:node:{uuid.uuid4()}")
    node_type:  CDGNodeType
    label:      str
    source_ref: Optional[str] = None   # e.g. "src/auth/JwtService.java:L42-L89"
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    detected_by: DetectionMethod = DetectionMethod.HYBRID
    metadata:   dict = Field(default_factory=dict)


# ── Node Types ────────────────────────────────────────────────────────────────

class CryptoAlgorithmNode(CDGNodeBase):
    """L1 — Classical cryptographic algorithm. Core migration candidate."""
    node_type: CDGNodeType = CDGNodeType.CRYPTO_ALGORITHM

    algorithm_family: str   # e.g. "RSA", "ECC", "AES"
    parameter_set: Optional[str] = None   # e.g. "RSA-2048", "ECC-P256"
    key_size_bits: Optional[int] = None
    use_context: Optional[str] = None     # e.g. "key_exchange", "digital_signature"

    quantum_vuln_class: NistQuantumVulnClass = NistQuantumVulnClass.UNKNOWN
    migration_priority: MigrationPriority = MigrationPriority.MEDIUM
    migration_urgency_score: float = Field(ge=0, le=100, default=0.0)
    hndl_risk: bool = False   # Harvest-Now-Decrypt-Later

    cbom_ref: Optional[str] = None   # CycloneDX bom-ref

    def is_quantum_vulnerable(self) -> bool:
        return self.quantum_vuln_class == NistQuantumVulnClass.QUANTUM_VULNERABLE

    def is_migration_required(self) -> bool:
        """Return True for any class that requires migration action."""
        return self.quantum_vuln_class in {
            NistQuantumVulnClass.QUANTUM_VULNERABLE,
            NistQuantumVulnClass.GROVER_WEAKENED,
        }

    @field_validator("key_size_bits")
    @classmethod
    def positive_key_size(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v <= 0:
            raise ValueError("key_size_bits must be positive")
        return v


class PQCAlgorithmNode(CDGNodeBase):
    """L0 — NIST-standardized PQC replacement algorithm."""
    node_type: CDGNodeType = CDGNodeType.PQC_ALGORITHM

    algorithm_id: PQCAlgorithmId
    fips_standard: str        # e.g. "FIPS 203"
    security_level: NistSecurityLevel
    primitive_type: str       # "KEM", "DSA"
    math_basis: str           # "lattice_mlwe", "hash_based", "code_based"

    replaces: List[str] = []  # classical algorithm families this replaces
    hybrid_mode_supported: bool = True
    liboqs_available: bool = True


class CryptoLibraryNode(CDGNodeBase):
    """L2 — Crypto library/framework (implements algorithms)."""
    node_type: CDGNodeType = CDGNodeType.CRYPTO_LIBRARY

    library_name: str
    version: Optional[str] = None
    language: str
    import_path: Optional[str] = None

    pqc_ready: bool = False
    pqc_version_min: Optional[str] = None
    cve_count: int = 0


class AppComponentNode(CDGNodeBase):
    """L3 — Application component that uses crypto."""
    node_type: CDGNodeType = CDGNodeType.APP_COMPONENT

    component_type: str   # "service", "class", "function", "api_endpoint"
    language: str
    file_path: Optional[str] = None
    lines_of_code: Optional[int] = None
    owns_crypto: bool = False
    is_boundary: bool = False   # external-facing / trust boundary


class ProtocolNode(CDGNodeBase):
    """L3 — Network/application protocol using crypto."""
    node_type: CDGNodeType = CDGNodeType.PROTOCOL

    protocol_name: str   # "TLS 1.2", "SSH-2", "JWT", etc.
    version: Optional[str] = None
    cipher_suites: List[str] = []
    quantum_vulnerable_handshake: bool = False
    hybrid_kem_supported: bool = False


class KeyMaterialNode(CDGNodeBase):
    """L2 — Cryptographic key or certificate material."""
    node_type: CDGNodeType = CDGNodeType.KEY_MATERIAL

    key_type: str         # "private_key", "certificate", "symmetric_key", etc.
    key_size_bits: Optional[int] = None
    storage_location: str = "unknown"
    data_lifetime_years: Optional[float] = None  # for HNDL risk scoring
    hardcoded: bool = False


class BusinessProcessNode(CDGNodeBase):
    """L4 — Business process / enterprise system that depends on crypto."""
    node_type: CDGNodeType = CDGNodeType.BUSINESS_PROCESS

    criticality: str = "medium"   # "critical", "high", "medium", "low"
    owner: Optional[str] = None
    data_classification: Optional[str] = None
    bssn_system_id: Optional[str] = None  # BSSN/SPBE system reference
    regulatory_scope: List[str] = []      # ["SPBE", "CNSA 2.0", "PP_82_2023"]


# ── Edges ─────────────────────────────────────────────────────────────────────

class CDGEdge(BaseModel):
    """Directed, typed edge between CDG nodes."""
    edge_id:    str = Field(default_factory=lambda: f"cdg:edge:{uuid.uuid4()}")
    edge_type:  CDGEdgeType
    source_id:  str
    target_id:  str
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    evidence:   Optional[str] = None   # supporting code snippet / LLM reasoning
    cbom_dep_type: Optional[str] = None  # "implements" | "uses" per IBM CBOM spec


# ── Migration Plan Item ───────────────────────────────────────────────────────

class MigrationItem(BaseModel):
    rank: int
    algo_node_id: str
    current_algorithm: str
    recommended_pqc: PQCAlgorithmId
    urgency_score: float
    affected_components: List[str] = []
    affected_processes: List[str] = []
    effort_estimate: str = "weeks"
    hybrid_mode_recommended: bool = True
    migration_notes: Optional[str] = None


class MigrationPlan(BaseModel):
    priority_queue: List[MigrationItem] = []
    total_vulnerable_assets: int = 0
    quantum_readiness_score: float = Field(ge=0, le=100, default=0.0)
    bssn_compliance_status: str = "unknown"


# ── CDG Document Root ─────────────────────────────────────────────────────────

CDGNode = (CryptoAlgorithmNode | PQCAlgorithmNode | CryptoLibraryNode |
           AppComponentNode | ProtocolNode | KeyMaterialNode | BusinessProcessNode)

class CDGDocument(BaseModel):
    """Root CDG document. Serializable to JSON for Neo4j import."""
    cdg_id:         str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: str = "1.0.0"
    generated_at:   datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generated_by:   str = "CryptoDep-LLM v1.0"

    target_repo: dict = Field(default_factory=dict)
    scan_stats:  dict = Field(default_factory=dict)

    nodes: List[dict] = []   # serialized CDGNode instances
    edges: List[CDGEdge] = []

    migration_plan: Optional[MigrationPlan] = None
    cbom_export:    Optional[str] = None   # BOM-Link to CycloneDX CBOM


# ── PQC Migration Lookup Table ────────────────────────────────────────────────

PQC_MIGRATION_TABLE = {
    "RSA": {
        "key_exchange": {
            "replacement": PQCAlgorithmId.ML_KEM_768,
            "hybrid": "X25519+ML-KEM-768 for TLS 1.3 hybrid mode.",
        },
        "digital_signature": {
            "replacement": PQCAlgorithmId.ML_DSA_65,
            "hybrid": "Ed25519+ML-DSA-65 for hybrid signing.",
        },
        "rationale": (
            "Context-dependent: RSA serves both KEM and signing. "
            "FIPS 203 (ML-KEM-768) for key exchange; FIPS 204 (ML-DSA-65) for signatures."
        ),
    },
    "ECC": {
        "key_exchange": {
            "replacement": PQCAlgorithmId.ML_KEM_768,
            "hybrid": "X25519+ML-KEM-768 (HPKE hybrid).",
        },
        "digital_signature": {
            "replacement": PQCAlgorithmId.ML_DSA_65,
            "hybrid": "Ed25519+ML-DSA-65 for hybrid signing.",
        },
        "rationale": (
            "Elliptic curve families split by primitive: "
            "ML-KEM-768 replaces ECDH/ECDHE; ML-DSA-65 replaces ECDSA."
        ),
    },
    "ECDH": {
        "key_exchange": {
            "replacement": PQCAlgorithmId.ML_KEM_768,
            "hybrid": "X25519+ML-KEM-768 (HPKE hybrid).",
        },
        "rationale": "ECDH is key-exchange-only. ML-KEM-768 (FIPS 203) is the direct replacement.",
    },
    "ECDSA": {
        "digital_signature": {
            "replacement": PQCAlgorithmId.ML_DSA_65,
            "hybrid": "Ed25519+ML-DSA-65 for hybrid signing.",
        },
        "rationale": "ECDSA is signature-only. ML-DSA-65 (FIPS 204, level 3) is the direct replacement.",
    },
    "DSA": {
        "digital_signature": {
            "replacement": PQCAlgorithmId.ML_DSA_65,
            "hybrid": None,
        },
        "rationale": "Legacy DSA is signature-only. Direct replacement with ML-DSA-65 recommended.",
    },
    "DH": {
        "key_exchange": {
            "replacement": PQCAlgorithmId.ML_KEM_768,
            "hybrid": "FFC-DH + ML-KEM-768 hybrid.",
        },
        "rationale": "Finite-field DH is key-exchange-only. ML-KEM-768 (FIPS 203) is the replacement.",
    },
}


# ── Urgency Score Formula ─────────────────────────────────────────────────────

def compute_urgency_score(
    vuln_class: NistQuantumVulnClass,
    business_criticality: str,
    data_lifetime_years: float,
    graph_centrality: float = 0.0,  # betweenness centrality in CDG [0–1]
    hndl_risk: bool = False,        # Harvest-Now-Decrypt-Later applies
    algo_family: str = "",          # e.g. "AES", "SHA2" — used for Grover reduction check
    key_size: int = 0,              # key/digest size in bits — used for Grover reduction check
) -> float:
    """
    Urgency = (V + Gv)*C*D*100 + centrality_bonus + hndl_bonus  (capped at 100)

    V:   vulnerability weight (quantum_vulnerable=1.0, else 0.0)
    Gv:  Grover reduction weight (0.4 for symmetric/hash with key_size < 256 bits)
    C:   criticality weight (critical=1.0, high=0.75, medium=0.5, low=0.25)
    D:   data lifetime weight (>=10y=1.0, >=5y=0.8, >=1y=0.5, <1y=0.2)
    centrality_bonus: graph betweenness centrality * 20  (up to +20)
    hndl_bonus: +10 for vulnerable nodes (Shor or Grover) with HNDL exposure

    Grover reduction: AES-128/SHA-256 provide only 64/128-bit quantum security —
    relevant for long-lived data protection (NIST SP 800-38B recommendation).
    """
    V = 1.0 if vuln_class == NistQuantumVulnClass.QUANTUM_VULNERABLE else 0.0

    # Grover reduction applies to symmetric/hash algorithms with insufficient key lengths
    _grover_families = {"AES", "SHA2", "SHA-2", "SHA256", "SHA-256", "HMAC", "SHA384", "SHA-384"}
    grover_vuln = (
        vuln_class in {NistQuantumVulnClass.QUANTUM_SAFE_SYMMETRIC, NistQuantumVulnClass.GROVER_WEAKENED}
        and key_size > 0
        and key_size < 256
        and algo_family.upper() in {f.upper() for f in _grover_families}
    )
    Gv = 0.4 if grover_vuln else 0.0

    C = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}.get(
        business_criticality.lower(), 0.5
    )
    D = 1.0 if data_lifetime_years >= 10 else \
        0.8 if data_lifetime_years >= 5  else \
        0.5 if data_lifetime_years >= 1  else 0.2
    G = min(max(graph_centrality, 0.0), 1.0)
    base             = (V + Gv) * C * D * 100
    centrality_bonus = G * 20
    hndl_bonus       = 10.0 if (hndl_risk and (V > 0.0 or Gv > 0.0)) else 0.0
    return round(min(base + centrality_bonus + hndl_bonus, 100.0), 2)


if __name__ == "__main__":
    # ── Smoke test: build a minimal CDG ──────────────────────────────────────
    rsa_node = CryptoAlgorithmNode(
        label="RSA-2048",
        algorithm_family="RSA",
        parameter_set="RSA-2048",
        key_size_bits=2048,
        use_context="key_exchange",
        quantum_vuln_class=NistQuantumVulnClass.QUANTUM_VULNERABLE,
        migration_priority=MigrationPriority.CRITICAL,
        hndl_risk=True,
        source_ref="src/auth/JwtService.java:L42",
    )

    mlkem_node = PQCAlgorithmNode(
        label="ML-KEM-768",
        algorithm_id=PQCAlgorithmId.ML_KEM_768,
        fips_standard="FIPS 203",
        security_level=NistSecurityLevel.L3,
        primitive_type="KEM",
        math_basis="lattice_mlwe",
        replaces=["RSA", "ECDH", "DH"],
    )

    bc_lib = CryptoLibraryNode(
        label="BouncyCastle 1.70",
        library_name="BouncyCastle",
        version="1.70",
        language="java",
        import_path="org.bouncycastle.jce.provider",
        pqc_ready=True,
        pqc_version_min="1.72",
    )

    jwt_service = AppComponentNode(
        label="JwtService",
        component_type="service",
        language="java",
        file_path="src/auth/JwtService.java",
        owns_crypto=True,
        is_boundary=True,
    )

    auth_process = BusinessProcessNode(
        label="Authentication System",
        criticality="critical",
        bssn_system_id="SPBE-AUTH-001",
        regulatory_scope=["SPBE", "PP_82_2023"],
    )

    edge_lib_algo = CDGEdge(
        edge_type=CDGEdgeType.IMPLEMENTS,
        source_id=bc_lib.node_id,
        target_id=rsa_node.node_id,
        evidence="BouncyCastle provides RSA via RSAKeyPairGenerator",
    )
    edge_comp_lib = CDGEdge(
        edge_type=CDGEdgeType.USES,
        source_id=jwt_service.node_id,
        target_id=bc_lib.node_id,
        evidence="import org.bouncycastle.jce.provider.BouncyCastleProvider",
    )
    edge_migration = CDGEdge(
        edge_type=CDGEdgeType.MIGRATES_TO,
        source_id=rsa_node.node_id,
        target_id=mlkem_node.node_id,
        evidence="FIPS 203 migration guidance: RSA→ML-KEM-768",
    )

    score = compute_urgency_score(
        NistQuantumVulnClass.QUANTUM_VULNERABLE,
        "critical", 10.0, 0.85
    )
    print(f"RSA-2048 urgency score: {score}/100")
    print(f"CDG nodes: RSA→ML-KEM via {edge_migration.edge_type.value}")
    rsa_kem = PQC_MIGRATION_TABLE['RSA']['key_exchange']['replacement']
    rsa_sig = PQC_MIGRATION_TABLE['RSA']['digital_signature']['replacement']
    print(f"PQC table RSA(KEM)→{rsa_kem.value}, RSA(sig)→{rsa_sig.value}")
    print("Smoke test PASSED.")
