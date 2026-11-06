"""Integration tests for `cryptodep eval --predicted-cdg` (M5).

These tests invoke the Typer CLI directly (no subprocess) and verify that:
  1. `eval` command accepts --predicted-cdg and exits 0
  2. The report shows all 6 PRD metrics as PASS when fixture_cdg.json matches fixture_gt.json perfectly
  3. --output saves a valid JSON results file
"""
from __future__ import annotations

import json
import pathlib
import tempfile

import pytest
from typer.testing import CliRunner

from cryptodep.cli import app

FIXTURE_CDG = str(pathlib.Path("tests/fixtures/fixture_cdg.json").resolve())
FIXTURE_GT  = str(pathlib.Path("tests/eval/ground_truth/fixture_gt.json").resolve())
SAMPLE_REPO = str(pathlib.Path("tests/fixtures/sample_repo").resolve())

runner = CliRunner()


def test_eval_predicted_cdg_exits_zero():
    """eval --predicted-cdg must exit 0 when CDG and GT are both valid."""
    result = runner.invoke(app, [
        "eval", SAMPLE_REPO, FIXTURE_GT,
        "--predicted-cdg", FIXTURE_CDG,
    ])
    assert result.exit_code == 0, result.output


def test_eval_predicted_cdg_all_pass():
    """eval on a perfect prediction must show PASS for all 6 PRD metrics."""
    result = runner.invoke(app, [
        "eval", SAMPLE_REPO, FIXTURE_GT,
        "--predicted-cdg", FIXTURE_CDG,
    ])
    assert result.exit_code == 0, result.output
    output = result.output
    assert "[FAIL]" not in output, (
        f"Expected all metrics to PASS but got FAILs:\n{output}"
    )
    assert "Targets met: 6/6" in output, f"Expected 6/6 targets met:\n{output}"


def test_eval_predicted_cdg_writes_output_json():
    """eval --output must write a JSON file with all metric keys."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        out_path = f.name

    result = runner.invoke(app, [
        "eval", SAMPLE_REPO, FIXTURE_GT,
        "--predicted-cdg", FIXTURE_CDG,
        "--output", out_path,
    ])
    assert result.exit_code == 0, result.output

    results = json.loads(pathlib.Path(out_path).read_text())
    required_keys = {
        "node_f1", "edge_f1", "multihop_recall",
        "spearman_rho", "critical_recall",
        "hallucination_rate", "token_efficiency", "throughput",
        "passes_node_f1", "passes_edge_f1", "passes_multihop_recall",
        "passes_spearman_rho", "passes_critical_recall",
        "passes_hallucination_rate",
    }
    assert required_keys.issubset(results.keys()), (
        f"Missing keys: {required_keys - results.keys()}"
    )
    assert results["node_f1"] == 1.0
    assert results["edge_f1"] == 1.0
    assert results["critical_recall"] == 1.0


def test_eval_missing_gt_exits_nonzero():
    """eval with a missing GT file must exit non-zero."""
    result = runner.invoke(app, [
        "eval", SAMPLE_REPO, "/nonexistent/gt.json",
        "--predicted-cdg", FIXTURE_CDG,
    ])
    assert result.exit_code != 0


def test_eval_missing_predicted_cdg_exits_nonzero():
    """eval with a missing --predicted-cdg file must exit non-zero."""
    result = runner.invoke(app, [
        "eval", SAMPLE_REPO, FIXTURE_GT,
        "--predicted-cdg", "/nonexistent/cdg.json",
    ])
    assert result.exit_code != 0
