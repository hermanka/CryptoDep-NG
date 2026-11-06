"""Typer CLI entry points for CryptoDep-LLM (PRD Section 8)."""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv

load_dotenv(override=True)  # .env always wins over stale shell exports

app = typer.Typer(
    name="cryptodep",
    help="CryptoDep-LLM: LLM-powered Crypto Dependency Graph construction for PQC migration planning.",
    no_args_is_help=True,
)


@app.command()
def run(
    repo_path: Path = typer.Argument(..., help="Local path to the target repository"),
    output: Path = typer.Option(Path("cdg_output.json"), "--output", help="CDG output JSON path"),
    report: Optional[Path] = typer.Option(None, "--report", help="Migration report Markdown path"),
    lang: str = typer.Option("en", "--lang", help="Report language [en|id]"),
    bssn_mode: bool = typer.Option(False, "--bssn-mode", help="Enable BSSN/SPBE regulatory framing"),
    local_llm: bool = typer.Option(False, "--local-llm", help="Use Ollama instead of Anthropic API"),
    neo4j_uri: str = typer.Option("bolt://localhost:7687", "--neo4j-uri", help="Neo4j connection URI"),
    db: Path = typer.Option(Path("cdg_store.db"), "--db", help="SQLite CDG store path"),
    skip_codeql: bool = typer.Option(False, "--skip-codeql", help="Skip optional CodeQL analysis"),
    reachability: bool = typer.Option(False, "--reachability", help="Enable A6 crypto reachability analysis"),
    verbose: bool = typer.Option(False, "--verbose", help="Show per-agent progress and token counts"),
    log_file: Optional[Path] = typer.Option(None, "--log-file", help="JSON-line log file path (default: logs/cryptodep_<ts>.log)"),
) -> None:
    """Run the full CryptoDep-LLM pipeline on a repository."""
    from cryptodep.pipeline import build_pipeline
    from cryptodep.config import CryptoDependConfig
    from cryptodep.logging_config import setup_logging
    import os

    resolved_log = setup_logging(str(log_file) if log_file else None)
    typer.echo(f"[CryptoDep-LLM] Scanning repository: {repo_path}")
    typer.echo(f"[CryptoDep-LLM] Logging -> {resolved_log}")
    _provider = os.environ.get("CRYPTODEP_LLM_PROVIDER", "anthropic")
    if local_llm:
        _provider = "ollama"
    config = CryptoDependConfig(
        llm_provider=_provider,  # type: ignore[arg-type]
        llm_base_url=os.environ.get("CRYPTODEP_LLM_BASE_URL", ""),
        llm_model=os.environ.get("CRYPTODEP_LLM_MODEL", ""),
        llm_api_key=os.environ.get("CRYPTODEP_LLM_API_KEY", ""),
        ollama_model=os.environ.get("CRYPTODEP_OLLAMA_MODEL", "qwen2.5-coder:7b"),
        openrouter_model=os.environ.get("CRYPTODEP_OPENROUTER_MODEL", "stepfun/step-3.5-flash:free"),
        groq_model=os.environ.get("CRYPTODEP_GROQ_MODEL", "llama-3.3-70b-versatile"),
        neo4j_uri=neo4j_uri,
        enable_neo4j=not bool(os.environ.get("CRYPTODEP_SKIP_NEO4J", "").strip()),
        neo4j_password=os.environ.get("NEO4J_PASSWORD", "password"),
        report_language=lang,  # type: ignore[arg-type]
        bssn_mode=bssn_mode,
        use_codeql=not skip_codeql,
        enable_reachability=reachability,
        sqlite_db_path=str(db),
    )
    from cryptodep.preflight import run_preflight_checks
    run_preflight_checks(config, repo_path=repo_path)
    pipeline = build_pipeline(config)
    pipeline.run(str(repo_path), output_path=str(output), report_path=str(report) if report else None, verbose=verbose)


@app.command()
def validate(
    cdg_path: Path = typer.Argument(..., help="Path to CDG JSON file to validate"),
) -> None:
    """Validate a CDG JSON file against schema v1.0."""
    from cryptodep.schema.cdg_models import CDGDocument
    import json

    typer.echo(f"Validating {cdg_path} ...")
    data = json.loads(cdg_path.read_text())
    CDGDocument.model_validate(data)
    typer.echo("[OK] CDG is valid.")


@app.command()
def diff(
    old_cdg: Path = typer.Argument(..., help="Path to the old CDG JSON"),
    new_cdg: Path = typer.Argument(..., help="Path to the new CDG JSON"),
) -> None:
    """Compare two CDG snapshots and report added/removed nodes and edges."""
    import json

    old = json.loads(old_cdg.read_text())
    new = json.loads(new_cdg.read_text())

    def _node_key(n: dict) -> tuple[str, str]:
        return (n["node_type"], n["label"])

    def _edge_key(e: dict) -> tuple[str, str, str]:
        # Ground-truth files use source_label/target_label; pipeline CDGs use source_id/target_id.
        src = e.get("source_label") or e.get("source_id", "?")
        tgt = e.get("target_label") or e.get("target_id", "?")
        return (src, e["edge_type"], tgt)

    old_nodes = {_node_key(n) for n in old.get("nodes", [])}
    new_nodes = {_node_key(n) for n in new.get("nodes", [])}
    old_edges = {_edge_key(e) for e in old.get("edges", [])}
    new_edges = {_edge_key(e) for e in new.get("edges", [])}

    added_nodes = sorted(new_nodes - old_nodes)
    removed_nodes = sorted(old_nodes - new_nodes)
    added_edges = sorted(new_edges - old_edges)
    removed_edges = sorted(old_edges - new_edges)

    if not any([added_nodes, removed_nodes, added_edges, removed_edges]):
        typer.echo("No changes.")
        return

    if added_nodes:
        typer.echo(f"Added nodes   ({len(added_nodes)}):  {[label for _, label in added_nodes]}")
    if removed_nodes:
        typer.echo(f"Removed nodes ({len(removed_nodes)}):  {[label for _, label in removed_nodes]}")
    if added_edges:
        typer.echo(f"Added edges   ({len(added_edges)}):  {[f'{s} --[{t}]--> {d}' for s, t, d in added_edges]}")
    if removed_edges:
        typer.echo(f"Removed edges ({len(removed_edges)}):  {[f'{s} --[{t}]--> {d}' for s, t, d in removed_edges]}")


@app.command(name="export-cbom")
def export_cbom(
    cdg_path: Path = typer.Argument(..., help="Path to CDG JSON file"),
    output: Optional[Path] = typer.Option(None, "--output", help="Output CBOM JSON path"),
) -> None:
    """Export a CDG as CycloneDX CBOM v1.6 JSON."""
    import json
    import types

    from cryptodep.tools.cbom_tools import cdg_to_cbom, export_cbom_json

    data = json.loads(cdg_path.read_text())
    # cdg_to_cbom only accesses .nodes (an iterable of node dicts); we pass a
    # minimal wrapper so we don't need to round-trip through CDGDocument validation.
    cdg_ns = types.SimpleNamespace(nodes=data.get("nodes", []))
    bom = cdg_to_cbom(cdg_ns)

    out_path = output if output is not None else cdg_path.parent / (cdg_path.stem + ".cdx.json")
    export_cbom_json(bom, str(out_path))
    typer.echo(f"CBOM written -> {out_path}")


@app.command()
def analyze(
    cbom_path: Path = typer.Argument(..., help="Path to CycloneDX CBOM JSON file"),
    output: Optional[Path] = typer.Option(None, "--output", help="Output Markdown path (default: <cbom>_analysis.md)"),
    db: Optional[Path] = typer.Option(None, "--db", help="SQLite CDG store path (default: auto-detect cdg_store.db next to CBOM)"),
    deep: bool = typer.Option(False, "--deep", help="Add LLM-generated deep analysis (section E)"),
) -> None:
    """Analyze a CBOM JSON file and produce a human-readable Markdown report."""
    import os
    from cryptodep.analysis.analyzer import CBOMAnalyzer

    if not cbom_path.exists():
        typer.echo(f"Error: CBOM file not found: {cbom_path}", err=True)
        raise typer.Exit(1)

    db_path = db
    if db_path is None:
        candidate = cbom_path.parent / "cdg_store.db"
        if candidate.exists():
            db_path = candidate

    analyzer = CBOMAnalyzer(cbom_path, db_path=db_path)

    config = None
    if deep:
        from cryptodep.config import CryptoDependConfig
        config = CryptoDependConfig(
            llm_provider=os.environ.get("CRYPTODEP_LLM_PROVIDER", "anthropic"),  # type: ignore[arg-type]
            ollama_model=os.environ.get("CRYPTODEP_OLLAMA_MODEL", "qwen2.5-coder:7b"),
            neo4j_password=os.environ.get("NEO4J_PASSWORD", "neo4j1234"),
        )

    result_path = analyzer.write(output_path=output, deep=deep, config=config)
    typer.echo(f"[analyze] Report written -> {result_path}")


@app.command()
def query(
    cypher_query: str = typer.Argument(..., help="Cypher query to run on the loaded CDG"),
    neo4j_uri: str = typer.Option("bolt://localhost:7687", "--neo4j-uri", help="Neo4j connection URI"),
) -> None:
    """Run an arbitrary Cypher query on the loaded CDG in Neo4j."""
    import json
    import os

    import neo4j
    from neo4j.exceptions import DriverError, Neo4jError

    password = os.environ.get("NEO4J_PASSWORD", "password")
    try:
        with neo4j.GraphDatabase.driver(neo4j_uri, auth=("neo4j", password)) as driver:
            with driver.session() as session:
                result = session.run(cypher_query)
                for record in result:
                    typer.echo(json.dumps(record.data()))
    except (Neo4jError, DriverError) as exc:
        typer.echo(f"Neo4j error at {neo4j_uri}: {exc}", err=True)
        raise typer.Exit(1)


@app.command()
def eval(
    repo_path: Path = typer.Argument(..., help="Path to benchmark repository (used if --predicted-cdg not given)"),
    ground_truth: Path = typer.Argument(..., help="Path to expert-annotated ground truth CDG JSON"),
    predicted_cdg: Optional[Path] = typer.Option(None, "--predicted-cdg", help="Pre-generated CDG JSON; skips pipeline run"),
    output: Optional[Path] = typer.Option(None, "--output", help="Evaluation results JSON output path"),
    neo4j_uri: str = typer.Option("bolt://localhost:7687", "--neo4j-uri", help="Neo4j connection URI"),
    clear_neo4j: bool = typer.Option(False, "--clear-neo4j", help="Clear Neo4j before running pipeline (prevents cross-run contamination)"),
    runs: int = typer.Option(1, "--runs", min=1, help="Number of independent pipeline runs for mean ± std statistics"),
    verbose: bool = typer.Option(False, "--verbose", help="Show per-agent progress"),
) -> None:
    """Run F1/MPQS evaluation against expert ground truth.

    If --predicted-cdg is supplied, use that CDG JSON and skip the pipeline run.
    Otherwise, run the full pipeline on repo_path first.
    Use --runs N to execute N independent runs and report mean ± std per metric.
    """
    import json
    import os
    import time

    from cryptodep.logging_config import setup_logging
    from tests.eval.eval_metrics import evaluate_all, resolve_edge_labels, _print_report, aggregate_multirun_results

    _log_path = setup_logging()
    typer.echo(f"[eval] Logging -> {_log_path}")

    gt_path = ground_truth
    if not gt_path.exists():
        typer.echo(f"[ERROR] Ground truth not found: {gt_path}", err=True)
        raise typer.Exit(1)

    ground_truth_data = json.loads(gt_path.read_text())

    def _run_once(run_index: int) -> dict:
        """Execute one full pipeline eval and return a results dict."""
        nonlocal clear_neo4j

        if predicted_cdg is not None:
            if not predicted_cdg.exists():
                typer.echo(f"[ERROR] Predicted CDG not found: {predicted_cdg}", err=True)
                raise typer.Exit(1)
            _predicted_data = json.loads(predicted_cdg.read_text())
            _elapsed = 0.0
            _total_tokens = 0
            if run_index == 0:
                typer.echo(f"[eval] Using pre-generated CDG: {predicted_cdg}")
        else:
            if clear_neo4j:
                import neo4j as _neo4j_mod
                from cryptodep.tools.neo4j_tools import clear_neo4j as _clear_fn, count_nodes_and_edges
                _password = os.environ.get("NEO4J_PASSWORD", "password")
                try:
                    _driver = _neo4j_mod.GraphDatabase.driver(
                        neo4j_uri, auth=("neo4j", _password), connection_timeout=5
                    )
                    with _driver.session() as _s:
                        _s.run("RETURN 1")
                    _before = count_nodes_and_edges(_driver)
                    typer.echo(
                        f"[eval] Clearing Neo4j ({_before['nodes']} nodes, "
                        f"{_before['edges']} edges) before run {run_index + 1}..."
                    )
                    _clear_fn(_driver)
                    _driver.close()
                    typer.echo("[eval] Neo4j cleared.")
                except Exception as _exc:  # noqa: BLE001
                    typer.echo(f"[eval] Warning: could not clear Neo4j: {_exc}", err=True)

            from cryptodep.pipeline import build_pipeline
            from cryptodep.config import CryptoDependConfig

            _provider = os.environ.get("CRYPTODEP_LLM_PROVIDER", "anthropic")
            _config = CryptoDependConfig(
                llm_provider=_provider,  # type: ignore[arg-type]
                anthropic_model=os.environ.get("CRYPTODEP_ANTHROPIC_MODEL", "claude-sonnet-4-6"),
                ollama_model=os.environ.get("CRYPTODEP_OLLAMA_MODEL", "qwen2.5-coder:7b"),
                openrouter_model=os.environ.get("CRYPTODEP_OPENROUTER_MODEL", "stepfun/step-3.5-flash:free"),
                groq_model=os.environ.get("CRYPTODEP_GROQ_MODEL", "llama-3.3-70b-versatile"),
                neo4j_uri=neo4j_uri,
                neo4j_password=os.environ.get("NEO4J_PASSWORD", "password"),
            )

            _pipeline = build_pipeline(_config)
            typer.echo(f"[eval] Run {run_index + 1}: pipeline on {repo_path} ...")
            _t0 = time.time()
            _cdg_tmp = Path(f"cdg_eval_tmp_{run_index}.json")
            try:
                _final_state = _pipeline.run(str(repo_path), output_path=str(_cdg_tmp), verbose=verbose)
                _elapsed = time.time() - _t0
                _predicted_data = json.loads(_cdg_tmp.read_text())
            finally:
                _cdg_tmp.unlink(missing_ok=True)
            _total_tokens = _final_state.get("total_llm_tokens", 0)

        _pred_nodes = _predicted_data.get("nodes", [])
        _pred_edges_raw = _predicted_data.get("edges", [])
        _pred_edges = resolve_edge_labels(_pred_edges_raw, _pred_nodes)

        # Resolve A3 proposed vs validated counts from scan_stats for accurate
        # hallucination_rate. Falls back to len(_pred_edges) for both when the
        # CDG was generated without these fields (rate = 0.0 in that case).
        _scan_stats = _predicted_data.get("scan_stats", {})
        _a3_proposed = _scan_stats.get("a3_proposed_edges", len(_pred_edges))
        _a3_validated = _scan_stats.get("a3_validated_edges", len(_pred_edges))
        _proposed_proxy = [{}] * _a3_proposed
        _validated_proxy = [{}] * _a3_validated

        return evaluate_all(
            predicted_cdg=_predicted_data,
            ground_truth=ground_truth_data,
            total_llm_tokens=_total_tokens,
            elapsed_seconds=_elapsed,
            proposed_edges=_proposed_proxy,
            validated_edges=_validated_proxy,
        )

    if runs == 1:
        results = _run_once(0)
        _print_report(repo_path.name, results)
        if output:
            output.write_text(json.dumps(results, indent=2))
            typer.echo(f"Results saved to {output}")
    else:
        typer.echo(f"[eval] Running {runs} independent pipeline runs ...")
        individual = [_run_once(i) for i in range(runs)]
        aggregated = aggregate_multirun_results(individual)
        typer.echo(f"\n[eval] Aggregated results over {runs} runs:")
        for metric, vals in aggregated["metrics"].items():
            pass_key = f"passes_{metric}"
            pass_str = ""
            if pass_key in aggregated["passes"]:
                pass_str = f"  [{'PASS' if aggregated['passes'][pass_key] else 'FAIL'}]"
            typer.echo(f"  {metric:30s} mean={vals['mean']:.3f}  std={vals['std']:.3f}{pass_str}")
        passes = sum(1 for v in aggregated["passes"].values() if v)
        total = len(aggregated["passes"])
        typer.echo(f"\n  Targets met (mean): {passes}/{total}")

        out_path = output or Path(f"eval_results/{repo_path.name}_results_{runs}runs.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(aggregated, indent=2))
        typer.echo(f"Multi-run results saved to {out_path}")


@app.command(name="clear-neo4j")
def clear_neo4j_cmd(
    neo4j_uri: str = typer.Option("bolt://localhost:7687", "--neo4j-uri", help="Neo4j connection URI"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
) -> None:
    """Delete ALL nodes and relationships from Neo4j (preflight clean slate).

    Use before running the pipeline or eval to prevent cross-run data
    accumulation. Requires explicit --yes or interactive confirmation.
    """
    import os
    import neo4j
    from neo4j.exceptions import DriverError, Neo4jError
    from cryptodep.tools.neo4j_tools import clear_neo4j, count_nodes_and_edges

    password = os.environ.get("NEO4J_PASSWORD", "password")
    try:
        driver = neo4j.GraphDatabase.driver(
            neo4j_uri,
            auth=("neo4j", password),
            connection_timeout=5,
            max_connection_lifetime=300,
        )
        with driver.session() as session:
            session.run("RETURN 1")
    except (Neo4jError, DriverError) as exc:
        typer.echo(f"[ERROR] Neo4j unreachable at {neo4j_uri}: {exc}", err=True)
        raise typer.Exit(1)

    before = count_nodes_and_edges(driver)
    typer.echo(
        f"[clear-neo4j] Current state: {before['nodes']} nodes, {before['edges']} edges at {neo4j_uri}"
    )

    if before["nodes"] == 0 and before["edges"] == 0:
        typer.echo("[clear-neo4j] Database already empty — nothing to do.")
        driver.close()
        return

    if not yes:
        confirmed = typer.confirm(
            f"⚠️  This will permanently delete ALL {before['nodes']} nodes and "
            f"{before['edges']} edges. Continue?"
        )
        if not confirmed:
            typer.echo("Aborted.")
            driver.close()
            raise typer.Exit(0)

    clear_neo4j(driver)
    after = count_nodes_and_edges(driver)
    driver.close()
    typer.echo(
        f"[clear-neo4j] Done — {before['nodes']} nodes and {before['edges']} edges deleted. "
        f"Remaining: {after['nodes']} nodes, {after['edges']} edges."
    )


@app.command(name="export-neo4j")
def export_neo4j(
    run_id: Optional[str] = typer.Option(None, "--run-id", help="Run ID to export; defaults to latest"),
    db: Path = typer.Option(Path("cdg_store.db"), "--db", help="SQLite CDG store path"),
    neo4j_uri: str = typer.Option("bolt://localhost:7687", "--neo4j-uri", help="Neo4j connection URI"),
) -> None:
    """Export a stored CDG from SQLite to Neo4j.

    Reads the CDG from cdg_store.db (or --db) and pushes all nodes and edges
    to Neo4j. Safe to run multiple times (MERGE semantics). Exits with code 1
    if Neo4j is unreachable.
    """
    import os

    import neo4j as _neo4j
    from neo4j.exceptions import DriverError, Neo4jError

    from cryptodep.tools.sqlite_tools import (
        get_connection,
        load_cdg_by_run_id,
        load_latest_cdg,
        list_runs,
    )
    from cryptodep.tools.neo4j_tools import (
        setup_constraints,
        upsert_node,
        upsert_edge,
    )
    from cryptodep.schema.cdg_models import CDGNodeType, CryptoAlgorithmNode, PQCAlgorithmNode

    if not db.exists():
        typer.echo(f"[ERROR] SQLite store not found: {db}", err=True)
        typer.echo("Hint: run 'cryptodep run <repo>' first to generate cdg_store.db", err=True)
        raise typer.Exit(1)

    conn = get_connection(str(db))
    try:
        if run_id:
            cdg_doc = load_cdg_by_run_id(conn, run_id)
            typer.echo(f"[export-neo4j] Loaded run {run_id} from {db}")
        else:
            runs = list_runs(conn)
            if not runs:
                typer.echo("[ERROR] No runs in SQLite store.", err=True)
                raise typer.Exit(1)
            cdg_doc = load_latest_cdg(conn)
            typer.echo(f"[export-neo4j] Loaded latest run ({runs[0]['run_id'][:8]}…) from {db}")
    except ValueError as exc:
        typer.echo(f"[ERROR] {exc}", err=True)
        raise typer.Exit(1)
    finally:
        conn.close()

    password = os.environ.get("NEO4J_PASSWORD", "password")
    try:
        driver = _neo4j.GraphDatabase.driver(
            neo4j_uri,
            auth=("neo4j", password),
            connection_timeout=5,
            max_connection_lifetime=300,
        )
        with driver.session() as session:
            session.run("RETURN 1")
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[ERROR] Neo4j unreachable at {neo4j_uri}: {exc}", err=True)
        typer.echo("Hint: start Neo4j and retry: cryptodep export-neo4j", err=True)
        raise typer.Exit(1)

    setup_constraints(driver)

    type_map = {
        CDGNodeType.CRYPTO_ALGORITHM: CryptoAlgorithmNode,
        CDGNodeType.PQC_ALGORITHM: PQCAlgorithmNode,
    }
    nodes_written = 0
    for node_dict in cdg_doc.nodes:
        node_type_str = node_dict.get("node_type", "")
        try:
            node_type = CDGNodeType(node_type_str)
            cls = type_map.get(node_type)
            if cls:
                upsert_node(driver, cls.model_validate(node_dict))
                nodes_written += 1
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"[warn] Skipped node {node_type_str}: {exc}", err=True)

    edges_written = 0
    for edge in cdg_doc.edges:
        try:
            upsert_edge(driver, edge)
            edges_written += 1
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"[warn] Skipped edge {edge.edge_id}: {exc}", err=True)

    driver.close()
    typer.echo(
        f"[export-neo4j] Done — {nodes_written} nodes, {edges_written} edges"
        f" written to {neo4j_uri}"
    )


if __name__ == "__main__":
    app()
