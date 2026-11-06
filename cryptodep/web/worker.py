"""One isolated scan process; never execute code from the cloned repository."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cryptodep.pipeline import build_pipeline
from cryptodep.schema.cdg_models import PQC_MIGRATION_TABLE
from cryptodep.web import store
from cryptodep.web.risk import annotate_risks
from cryptodep.web.app import ai_config, repository_url


def clone_repository(url: str, destination: Path, log_path: Path):
    url = repository_url(url)
    hooks = destination.parent / "empty-hooks"
    hooks.mkdir(exist_ok=True)
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_CONFIG")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_LFS_SKIP_SMUDGE="1")
    command = ["git", "-c", f"core.hooksPath={hooks}", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
               "clone", "--depth=1", "--single-branch", "--no-recurse-submodules", "--", url + ".git", str(destination)]
    with log_path.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(command, stdout=output, stderr=output, env=env)
        start = time.monotonic()
        try:
            while True:
                finished = process.poll() is not None
                size = 0
                for path in destination.rglob("*"):
                    try:
                        if not path.is_symlink() and path.is_file():
                            size += path.stat().st_size
                    except FileNotFoundError:
                        continue
                if time.monotonic() - start > 180 or size > 512 * 1024 * 1024:
                    raise RuntimeError("Clone melewati batas 3 menit atau ukuran 512 MB.")
                if finished:
                    break
                time.sleep(1)
            if process.returncode:
                raise RuntimeError("Clone gagal. Pastikan URL repository GitHub publik dapat diakses.")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
    return subprocess.check_output(["git", "-C", str(destination), "rev-parse", "HEAD"], env=env, text=True).strip()


def enrich_document(document: dict, state: dict, repo: Path, url: str, commit: str) -> dict:
    """Attach existing findings and deterministic recommendations for the detail panel."""
    document["target_repo"].update(url=url, name=url.rsplit("/", 1)[-1], commit=commit)
    findings = []
    for finding in state.get("validated_findings", []):
        match = re.fullmatch(r"(.+):L?(\d+)(?:-L?\d+)?", finding.get("source_ref", ""))
        if not match:
            continue
        path, line = match.groups()
        cached = state.get("ast_cache", {}).get(path)
        try:
            relative = Path(path).resolve().relative_to(repo.resolve()).as_posix()
        except ValueError:
            continue
        if cached is None:
            continue
        number = int(line)
        lines = cached["source"].splitlines()
        if not 1 <= number <= len(lines):
            continue
        findings.append({**finding, "source_ref": f"{relative}:L{number}", "file": relative, "line": number,
                         "evidence": "\n".join(lines[max(0, number - 2):number + 2])})
    for node in document["nodes"]:
        metadata = node.setdefault("metadata", {})
        if node["node_type"] == "CryptoAlgorithm":
            metadata["findings"] = [f for f in findings if f["algorithm_family"] == node.get("algorithm_family")]
            mapping = PQC_MIGRATION_TABLE.get(node.get("algorithm_family"), {})
            metadata["migration_suggestions"] = [
                {"context": context, "algorithm": entry["replacement"].value,
                 "hybrid": entry.get("hybrid"), "reason": mapping.get("rationale", "")}
                for context, entry in mapping.items() if isinstance(entry, dict) and "replacement" in entry
            ]
            if node.get("quantum_vuln_class") == "grover_weakened":
                metadata["migration_suggestions"].append({"context": "symmetric", "algorithm": "Perbesar ukuran kunci/parameter",
                                                          "reason": "Tinjau ukuran kunci serta konteks penggunaan; penggantian ke PQC tidak selalu diperlukan."})
        for field in ("source_ref", "file_path"):
            value = node.get(field)
            if value and str(repo) in value:
                node[field] = value.replace(str(repo) + os.sep, "").replace("\\", "/")
    document["scan_stats"].update(state.get("repo_stats", {}))
    document["scan_stats"]["findings_count"] = len(findings)
    document["analysis_notes"] = [
        "Analisis statis Java, Python, dan dukungan awal JavaScript. Hubungan import tidak membuktikan pemanggilan saat runtime.",
        "Komponen ditampilkan pada tingkat file/class; graph ini bukan call graph lengkap setiap fungsi.",
        "Abu-abu bukan bukti keamanan umum. Klasifikasi PQC tidak menilai seluruh kelemahan kriptografi klasik.",
    ]
    return annotate_risks(document)


def run_scan(root: Path, scan_id: str, settings: dict):
    work = root / scan_id
    repo = work / "repo"
    scan = store.get_scan(root, scan_id)
    try:
        store.progress(root, scan_id, "clone", "running")
        commit = clone_repository(scan["repo_url"], repo, work / "clone.log")
        store.update(root, scan_id, commit_sha=commit)
        store.progress(root, scan_id, "clone", "completed")
        config = ai_config(settings)
        config.sqlite_db_path = str(work / "cdg.db")
        config.use_codeql = False
        os.chdir(work)
        os.environ["SEMGREP_SEND_METRICS"] = "off"
        os.environ["SEMGREP_ENABLE_VERSION_CHECK"] = "0"
        state = build_pipeline(config).run(str(repo), output_path=str(work / "cdg.json"),
                                           report_path=str(work / "report.md"),
                                           progress=lambda stage, status: store.progress(root, scan_id, stage, status))
        if not state.get("file_index"):
            raise RuntimeError("Tidak ada file Java/Python/JavaScript yang berhasil dianalisis.")
        document = json.loads((work / "cdg.json").read_text(encoding="utf-8"))
        document = enrich_document(document, state, repo, scan["repo_url"], commit)
        errors = state.get("errors", [])
        document["analysis_errors"] = [{"agent": error["agent"], "type": error["error_type"]} for error in errors]
        (work / "result.json").write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        if state.get("cbom_export_path"):
            shutil.copyfile(state["cbom_export_path"], work / "cbom.json")
        summary = {"nodes": len(document["nodes"]), "edges": len(document["edges"]),
                   "files": len(state["file_index"]), "findings": document["scan_stats"]["findings_count"],
                   "requires_migration": sum(n.get("quantum_vuln_class") in ("quantum_vulnerable", "grover_weakened") for n in document["nodes"])}
        store.update(root, scan_id, status="partial" if errors else "completed", summary=summary,
                     error="Sebagian tahap memiliki keterbatasan. Lihat rinciannya di Log proses." if errors else None)
    except Exception as exc:
        steps = store.get_scan(root, scan_id)["progress"]
        steps = {stage: "failed" if status == "running" else status for stage, status in steps.items()}
        # Do not expose arbitrary library exceptions, request payloads, or credentials.
        message = str(exc) if isinstance(exc, RuntimeError) and str(exc).startswith(("Clone", "Tidak ada", "Semgrep")) else "Pemindaian gagal pada tahap aktif. Periksa konfigurasi AI dan coba kembali."
        store.update(root, scan_id, status="failed", progress=steps, error=message)


if __name__ == "__main__":
    root = Path(os.environ["CRYPTODEP_WEB_DATA_DIR"]).resolve()
    run_scan(root, sys.argv[1], json.loads(sys.stdin.read()))
