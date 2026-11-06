"""PQC Migration Lookup Table (PRD Appendix B).

Maps classical algorithm families to their NIST-recommended PQC replacements.
Used by A4:CDGBuilder to automatically add migrates_to edges.

Import: from cryptodep.schema.pqc_lookup import PQC_MIGRATION_TABLE
"""
from __future__ import annotations

from cryptodep.schema.cdg_models import PQCAlgorithmId

# Re-export from cdg_models for convenience
from cryptodep.schema.cdg_models import PQC_MIGRATION_TABLE, compute_urgency_score

__all__ = [
    "PQC_MIGRATION_TABLE",
    "compute_urgency_score",
    "NIST_PQC_FAMILIES",
    "QUANTUM_VULNERABLE_FAMILIES",
    "QUANTUM_SAFE_SYMMETRIC_FAMILIES",
    "GROVER_WEAKENED_FAMILIES",
]

#: Algorithms that are quantum-vulnerable and require migration
QUANTUM_VULNERABLE_FAMILIES: frozenset[str] = frozenset({
    "RSA", "ECC", "ECDH", "ECDSA", "DSA", "DH",
})

#: Algorithms that are quantum-safe symmetric (no replacement needed)
QUANTUM_SAFE_SYMMETRIC_FAMILIES: frozenset[str] = frozenset({
    "AES", "SHA3", "SHA-3", "ChaCha20", "Poly1305",
    "BCRYPT", "SCRYPT", "ARGON2",
    # MD5/SHA-1 are classically weak but not quantum-vulnerable (Shor's doesn't apply to hashes).
    "MD5", "SHA-1", "SHA-256", "SHA-512", "SHA-384", "SHA", "HMAC",
})

#: NIST-standardized PQC algorithm families (Q2 decision tree gate)
NIST_PQC_FAMILIES: frozenset[str] = frozenset({
    "ML-KEM", "MLKEM", "ML_KEM",
    "ML-DSA", "MLDSA", "ML_DSA",
    "SLH-DSA", "SLHDSA", "SLH_DSA",
    "FN-DSA", "FNDSA", "FN_DSA",
    "HQC",
})

#: Symmetric families subject to Grover's algorithm weakening (Q3 check uses key_bits < 256)
GROVER_WEAKENED_FAMILIES: frozenset[str] = frozenset({"AES", "SHA", "SHA2", "SHA3", "HMAC"})

#: AES key sizes that are Grover-safe (>= 256 bits)
GROVER_SAFE_AES_KEY_SIZES: frozenset[int] = frozenset({256})

#: Default hybrid mode recommendations per algorithm family
HYBRID_RECOMMENDATIONS: dict[str, str | None] = {
    "RSA":   "X25519+ML-KEM-768 (TLS 1.3 hybrid)",
    "ECDH":  "X25519+ML-KEM-768 (HPKE hybrid)",
    "ECDSA": "Ed25519+ML-DSA-65",
    "DSA":   None,
    "ECC":   "Hybrid recommended during migration window",
    "DH":    "FFC-DH + ML-KEM-768 hybrid",
}
