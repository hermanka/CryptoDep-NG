"""Preflight dependency checks for `cryptodep run` (and `eval` with pipeline).

Checks run before the pipeline starts. All failures are collected and reported
together, then the process aborts with exit code 1.

Usage:
    from cryptodep.preflight import run_preflight_checks
    run_preflight_checks(config)  # raises SystemExit(1) on any failure
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, List, Optional

import structlog

log = structlog.get_logger().bind(module="preflight")


def check_repo(repo_path: Path) -> None:
    """Verify the target repository path exists and is a directory.

    Raises SystemExit(1) with a helpful message on failure.
    """
    if not repo_path.exists():
        print(
            f"[preflight] [FAIL] Repository path not found: {repo_path}\n"
            f"  -> Check the path is correct and accessible\n"
            f"  -> Usage: cryptodep run <path-to-repo>",
            file=sys.stderr,
        )
        raise SystemExit(1)
    if not repo_path.is_dir():
        print(
            f"[preflight] [FAIL] Repository path is not a directory: {repo_path}\n"
            f"  -> Provide a directory path, not a file",
            file=sys.stderr,
        )
        raise SystemExit(1)
    print(f"[preflight] [OK] Repository found ({repo_path})")


def check_neo4j(config: Any) -> None:
    """Verify Neo4j is reachable and credentials are valid.

    Raises SystemExit(1) with a helpful message on failure.
    """
    import neo4j
    from neo4j.exceptions import AuthError, ServiceUnavailable

    driver = neo4j.GraphDatabase.driver(
        config.neo4j_uri,
        auth=(config.neo4j_user, config.neo4j_password),
        connection_timeout=3.0,
    )
    try:
        driver.verify_connectivity()
        print(f"[preflight] [OK] Neo4j connected ({config.neo4j_uri})")
    except AuthError:
        print(
            f"[preflight] [FAIL] Neo4j authentication failed ({config.neo4j_uri})\n"
            f"  -> Check NEO4J_PASSWORD in .env matches the container password\n"
            f"  -> Container was started with: -e NEO4J_AUTH=neo4j/<password>",
            file=sys.stderr,
        )
        raise SystemExit(1)
    except (ServiceUnavailable, Exception) as exc:
        print(
            f"[preflight] [FAIL] Neo4j not reachable at {config.neo4j_uri}: {exc}\n"
            f"  -> Start the container:\n"
            f"    docker run --name neo4j -p7474:7474 -p7687:7687 \\\n"
            f"      -e NEO4J_AUTH=neo4j/<password> neo4j:5-community\n"
            f"  -> Or set --neo4j-uri to the correct URI",
            file=sys.stderr,
        )
        raise SystemExit(1)
    finally:
        driver.close()


def check_llm(config: Any) -> None:
    """Verify the configured LLM provider is ready (shallow check).

    - anthropic / openrouter: checks that the API key env var is set
    - ollama: checks that the Ollama HTTP endpoint is reachable

    Raises SystemExit(1) with a helpful message on failure.
    """
    import httpx

    provider = config.llm_provider

    if provider == "anthropic":
        if not os.environ.get("ANTHROPIC_API_KEY", "").strip():
            print(
                "[preflight] [FAIL] ANTHROPIC_API_KEY not set in environment\n"
                "  -> Add to .env: ANTHROPIC_API_KEY=sk-ant-...\n"
                "  -> Get key at: https://console.anthropic.com/settings/keys",
                file=sys.stderr,
            )
            raise SystemExit(1)
        print("[preflight] [OK] ANTHROPIC_API_KEY present")

    elif provider == "openrouter":
        if not os.environ.get("OPENROUTER_API_KEY", "").strip():
            print(
                "[preflight] [FAIL] OPENROUTER_API_KEY not set in environment\n"
                "  -> Add to .env: OPENROUTER_API_KEY=sk-or-...\n"
                "  -> Get key at: https://openrouter.ai/settings/keys",
                file=sys.stderr,
            )
            raise SystemExit(1)
        print("[preflight] [OK] OPENROUTER_API_KEY present")

    elif provider == "groq":
        if not os.environ.get("GROQ_API_KEY", "").strip():
            print(
                "[preflight] [FAIL] GROQ_API_KEY not set in environment\n"
                "  -> Add to .env: GROQ_API_KEY=gsk_...\n"
                "  -> Get key at: https://console.groq.com/keys",
                file=sys.stderr,
            )
            raise SystemExit(1)
        print("[preflight] [OK] GROQ_API_KEY present")

    elif provider == "openai_compatible":
        if not config.llm_base_url or not config.llm_model:
            print("[preflight] [FAIL] Set CRYPTODEP_LLM_BASE_URL and CRYPTODEP_LLM_MODEL", file=sys.stderr)
            raise SystemExit(1)
        print("[preflight] [OK] Compatible endpoint configured")

    elif provider == "ollama":
        base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        try:
            httpx.get(f"{base_url}/api/tags", timeout=2.0)
            print(f"[preflight] [OK] Ollama reachable ({base_url})")
        except Exception as exc:
            print(
                f"[preflight] [FAIL] Ollama not reachable at {base_url}: {exc}\n"
                f"  -> Start Ollama locally: ollama serve\n"
                f"  -> Or set OLLAMA_BASE_URL in .env to the correct endpoint",
                file=sys.stderr,
            )
            raise SystemExit(1)


def run_preflight_checks(config: Any, repo_path: Optional[Path] = None) -> None:
    """Run all preflight checks. Collects all failures, then aborts if any failed.

    Prints a summary to stdout. Raises SystemExit(1) if any check failed.
    """
    print("[preflight] Checking dependencies...")

    failures: List[str] = []

    checks = []
    if repo_path is not None:
        checks.append(("repo", lambda: check_repo(repo_path)))
    # CRYPTODEP_SKIP_NEO4J=1 disables the Neo4j preflight check (SQLite-only mode).
    # A4 already handles Neo4j as best-effort — this only skips the hard abort.
    if getattr(config, "enable_neo4j", True) and not os.environ.get("CRYPTODEP_SKIP_NEO4J", "").strip():
        checks.append(("neo4j", lambda: check_neo4j(config)))
    else:
        print("[preflight] [SKIP] Neo4j check disabled (CRYPTODEP_SKIP_NEO4J=1)")
    checks += [
        ("llm", lambda: check_llm(config)),
    ]

    for name, check_fn in checks:
        try:
            check_fn()
        except SystemExit:
            failures.append(name)

    if failures:
        print(
            f"\n[preflight] {len(failures)} check(s) failed. Aborting.",
            file=sys.stderr,
        )
        raise SystemExit(1)

    print("[preflight] [OK] All checks passed.")
