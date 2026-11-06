"""Agent 1 — Code Ingestion Agent (PRD Section 5.1).

Responsibility:
  Parse target repository, extract file structure, build AST representations for
  Java and Python source files, generate file dependency graph, populate CDGState.

Acceptance criteria (M2):
  AC-A1-01: Parse 100% of .java/.py files without crashing (graceful skip + log)
  AC-A1-02: Import graph completeness >= 95% on WebGoat benchmark
  AC-A1-03: Parse 100k LOC in < 60 seconds on M1/Intel Core i7
"""
from __future__ import annotations

import time
from typing import Any, Dict

from cryptodep.agents import BaseAgent
from cryptodep.state import CDGState
from cryptodep.tools.ast_tools import (
    EXT_LANG,
    build_file_graph,
    filter_source_files,
    parse_file_ast,
)


class CodeIngestionAgent(BaseAgent):
    agent_name = "A1:CodeIngestion"

    async def run(self, state: CDGState) -> CDGState:
        config = state["config"]
        t0 = time.monotonic()
        self.log.info("ingestion_start", repo=state["repo_path"])

        files = filter_source_files(
            state["repo_path"],
            config.languages,
            config.exclude_patterns,
        )

        file_index: Dict[str, Any] = {}
        ast_cache: Dict[str, Any] = {}
        errors = list(state.get("errors", []))
        lang_counts: Dict[str, int] = {}

        for path in files:
            language = EXT_LANG.get(path.suffix, "unknown")
            result = parse_file_ast(path, language)

            if result is None:
                errors.append({
                    "agent": self.agent_name,
                    "error_type": "parse_failed",
                    "message": f"Failed to parse {path}",
                    "recoverable": True,
                })
                continue

            source = result["source"]
            loc = source.count("\n") + 1
            path_str = str(path)

            file_index[path_str] = {
                "path": path_str,
                "language": language,
                "size_bytes": path.stat().st_size,
                "loc": loc,
            }
            ast_cache[path_str] = result
            lang_counts[language] = lang_counts.get(language, 0) + 1

        import_graph = build_file_graph(file_index, ast_cache)

        total_loc = sum(f["loc"] for f in file_index.values())
        repo_stats = {
            "total_files": len(file_index),
            "total_loc": total_loc,
            "languages": lang_counts,
        }

        elapsed = time.monotonic() - t0
        timings = dict(state.get("agent_timings", {}))
        timings[self.agent_name] = elapsed

        self.log.info(
            "ingestion_complete",
            files=len(file_index),
            loc=total_loc,
            elapsed=round(elapsed, 2),
        )

        state.update({
            "file_index": file_index,
            "ast_cache": ast_cache,
            "import_graph": import_graph,
            "repo_stats": repo_stats,
            "errors": errors,
            "agent_timings": timings,
        })
        return state
