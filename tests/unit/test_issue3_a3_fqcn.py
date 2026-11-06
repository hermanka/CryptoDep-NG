"""Tests for Issue 3: A3 BFS falsely rejects valid FQCN crypto lib edges.

Real failure scenario: Java wildcard imports store 'org.bouncycastle.jce.provider.*'.
_import_matches_target cannot match that against a FQCN class target like
'org.bouncycastle.jce.provider.BouncyCastleProvider'.

Also: Python 'from cryptography.hazmat.primitives.asymmetric import rsa' stores
the module path 'cryptography.hazmat.primitives.asymmetric', which doesn't contain
the target class 'cryptography.hazmat.primitives.asymmetric.rsa'.

Fix: crypto-lib prefix shortcut — if target_ref starts with a known crypto lib
prefix AND source file's import list contains a string that is a prefix of (or
prefix-matched to) the target, return a high score without requiring full BFS.

RED tests — these should fail before the fix.
"""
from __future__ import annotations

import pytest


# ── Wildcard import scenario (Java) ──────────────────────────────────────────

def test_wildcard_bouncycastle_import_accepted():
    """BouncyCastle wildcard import must score > min_edge_support for FQCN target."""
    from cryptodep.agents.a3_reasoning import _build_import_graph_support

    # Java: import org.bouncycastle.jce.provider.*;
    import_graph = {
        "src/AuthService.java": [
            "org.bouncycastle.jce.provider.*",   # wildcard — stored as-is from AST
            "java.security.KeyPairGenerator",
        ]
    }
    # LLM proposes target = FQCN of a class inside that package
    support = _build_import_graph_support(
        "src/AuthService.java",
        "org.bouncycastle.jce.provider.BouncyCastleProvider",
        import_graph,
        max_hops=4,
    )
    assert support > 0.25, (
        f"Wildcard BouncyCastle import should accept FQCN target, got {support}"
    )


def test_wildcard_javax_crypto_import_accepted():
    """javax.crypto wildcard import must accept FQCN class target."""
    from cryptodep.agents.a3_reasoning import _build_import_graph_support

    import_graph = {
        "src/Encryptor.java": [
            "javax.crypto.*",
            "java.security.*",
        ]
    }
    support = _build_import_graph_support(
        "src/Encryptor.java",
        "javax.crypto.Cipher",
        import_graph,
        max_hops=4,
    )
    assert support > 0.25, (
        f"javax.crypto.* wildcard import should accept Cipher FQCN, got {support}"
    )


# ── Python from-import scenario ───────────────────────────────────────────────

def test_python_from_cryptography_import_accepted():
    """Python 'from cryptography.hazmat.primitives.asymmetric import rsa' stores
    the module path. FQCN target 'cryptography.hazmat.primitives.asymmetric.rsa'
    must score > min_edge_support.
    """
    from cryptodep.agents.a3_reasoning import _build_import_graph_support

    # Python from-import stores the module part, not the attribute
    import_graph = {
        "app/crypto_utils.py": [
            "cryptography.hazmat.primitives.asymmetric",  # from cryptography...asymmetric import rsa
        ]
    }
    support = _build_import_graph_support(
        "app/crypto_utils.py",
        "cryptography.hazmat.primitives.asymmetric.rsa",
        import_graph,
        max_hops=4,
    )
    assert support > 0.25, (
        f"Python cryptography module path should match FQCN target, got {support}"
    )


# ── Non-crypto lib prefix is NOT boosted ─────────────────────────────────────

def test_non_crypto_wildcard_not_boosted():
    """java.util wildcard import must NOT get the crypto-prefix shortcut boost."""
    from cryptodep.agents.a3_reasoning import _build_import_graph_support

    import_graph = {
        "src/Util.java": [
            "java.util.*",
        ]
    }
    # java.util is not in _CRYPTO_LIB_PREFIXES — shortcut must not apply
    support = _build_import_graph_support(
        "src/Util.java",
        "java.util.ArrayList",
        import_graph,
        max_hops=4,
    )
    # Should score 0.0 — no path found (java.util.* wildcard can't be BFS-matched
    # to java.util.ArrayList without the crypto shortcut)
    assert support <= 0.25, (
        f"Non-crypto wildcard should not get boost, got {support}"
    )


def test_crypto_wildcard_not_boosted_if_target_unrelated():
    """Even with a crypto wildcard import, unrelated target must not be boosted."""
    from cryptodep.agents.a3_reasoning import _build_import_graph_support

    import_graph = {
        "src/Service.java": [
            "org.bouncycastle.jce.provider.*",
        ]
    }
    # Target is from a different (non-crypto) package entirely
    support = _build_import_graph_support(
        "src/Service.java",
        "com.example.internal.BusinessLogic",  # not a crypto lib
        import_graph,
        max_hops=4,
    )
    assert support <= 0.25, (
        f"Unrelated target should not be boosted by crypto wildcard import, got {support}"
    )


# ── Exact match still works (regression) ─────────────────────────────────────

def test_exact_fqcn_match_still_scores_1_0():
    """Exact FQCN match (import_graph value == target) must still return 1.0."""
    from cryptodep.agents.a3_reasoning import _build_import_graph_support

    import_graph = {
        "src/AuthService.java": [
            "org.bouncycastle.jce.provider.BouncyCastleProvider",
        ]
    }
    support = _build_import_graph_support(
        "src/AuthService.java",
        "org.bouncycastle.jce.provider.BouncyCastleProvider",
        import_graph,
        max_hops=4,
    )
    assert support == 1.0, f"Exact match must return 1.0, got {support}"
