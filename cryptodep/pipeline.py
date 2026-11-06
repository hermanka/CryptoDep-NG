"""LangGraph StateGraph pipeline assembly (PRD Section 4.1).

Pipeline flow:
  Repo Input -> A1 -> A2 -> A3 -> A4 -> A5 -> CDG Output + Migration Report
"""
from __future__ import annotations

import uuid
from typing import Callable, Optional

from cryptodep.config import CryptoDependConfig
from cryptodep.state import CDGState
from cryptodep.tools.state_validation import validate_state


class CryptoDependPipeline:
    """Assembled LangGraph StateGraph for the CryptoDep-LLM pipeline."""

    def __init__(self, config: CryptoDependConfig) -> None:
        self.config = config
        self._graph = self._build_graph()

    def _build_graph(self):  # type: ignore[return]
        """Build the LangGraph StateGraph. Agents are stubs until M2–M4."""
        try:
            from langgraph.graph import StateGraph
            from cryptodep.agents.a1_ingestion import CodeIngestionAgent
            from cryptodep.agents.a2_detection import CryptoDetectionAgent
            from cryptodep.agents.a3_reasoning import DependencyReasoningAgent
            from cryptodep.agents.a4_builder import CDGBuilderAgent
            from cryptodep.agents.a5_planner import MigrationPlannerAgent

            a1 = CodeIngestionAgent(self.config)
            a2 = CryptoDetectionAgent(self.config)
            a3 = DependencyReasoningAgent(self.config)
            a4 = CDGBuilderAgent(self.config)
            a5 = MigrationPlannerAgent(self.config)

            graph = StateGraph(CDGState)
            graph.add_node(
                "a1_ingestion",
                CryptoDependPipeline._make_validated_node(a1.run, "A1:CodeIngestion"),
            )
            graph.add_node(
                "a2_detection",
                CryptoDependPipeline._make_validated_node(a2.run, "A2:CryptoDetection"),
            )
            graph.add_node(
                "a3_reasoning",
                CryptoDependPipeline._make_validated_node(a3.run, "A3:DependencyReasoning"),
            )
            graph.add_node(
                "a4_builder",
                CryptoDependPipeline._make_validated_node(a4.run, "A4:CDGBuilder"),
            )
            graph.add_node(
                "a5_planner",
                CryptoDependPipeline._make_validated_node(a5.run, "A5:MigrationPlanner"),
            )

            if self.config.enable_reachability:
                from cryptodep.agents.a6_reachability import ReachabilityAgent
                a6 = ReachabilityAgent(self.config)
                graph.add_node(
                    "a6_reachability",
                    CryptoDependPipeline._make_validated_node(a6.run, "A6:Reachability"),
                )

            graph.set_entry_point("a1_ingestion")
            graph.add_edge("a1_ingestion", "a2_detection")
            graph.add_edge("a2_detection", "a3_reasoning")

            if self.config.enable_reachability:
                graph.add_edge("a3_reasoning", "a6_reachability")
                graph.add_edge("a6_reachability", "a4_builder")
            else:
                graph.add_edge("a3_reasoning", "a4_builder")

            graph.add_edge("a4_builder", "a5_planner")
            graph.set_finish_point("a5_planner")

            return graph.compile()
        except ImportError as e:
            raise RuntimeError(f"LangGraph not installed. Run `uv sync` first. ({e})") from e

    def _make_initial_state(self, repo_path: str) -> CDGState:
        """Return a freshly initialised CDGState for a pipeline run.

        Centralised here so both ``run()`` and integration tests build the
        same state, keeping the key set in sync with ``CDGState``'s definition.
        """
        return {
            "repo_path": repo_path,
            "config": self.config,
            "run_id": str(uuid.uuid4()),
            "file_index": {},
            "ast_cache": {},
            "import_graph": {},
            "repo_stats": {"total_files": 0, "total_loc": 0, "languages": {}},
            "raw_crypto_findings": [],
            "validated_findings": [],
            "candidate_edges": [],
            "validated_edges": [],
            "cdg_document": None,
            "neo4j_import_stats": {},
            "cbom_export_path": "",
            "sqlite_db_path": "",
            "migration_plan": None,
            "report_md": "",
            "errors": [],
            "agent_timings": {},
            "total_llm_tokens": 0,
            "entry_points": [],
            "call_graph": {},
            "reachability_map": {},
            "reachability_paths": {},
            "reachability_mode": "disabled",
        }

    def run(
        self,
        repo_path: str,
        output_path: str = "cdg_output.json",
        report_path: Optional[str] = None,
        verbose: bool = False,
        progress: Optional[Callable[[str, str], None]] = None,
    ) -> CDGState:
        """Execute the full pipeline and write outputs."""
        import asyncio
        import json

        initial_state = self._make_initial_state(repo_path)

        if verbose:
            print(f"[pipeline] run_id={initial_state['run_id']}")

        if progress is None:
            final_state: CDGState = asyncio.run(self._graph.ainvoke(initial_state))
        else:
            stages = ["a1_ingestion", "a2_detection", "a3_reasoning"]
            if self.config.enable_reachability:
                stages.append("a6_reachability")
            stages += ["a4_builder", "a5_planner"]

            async def run_with_progress():
                final = dict(initial_state)
                progress(stages[0], "running")
                async for update in self._graph.astream(initial_state, stream_mode="updates"):
                    for stage, values in update.items():
                        final.update(values)
                        progress(stage, "completed")
                        index = stages.index(stage)
                        if index + 1 < len(stages):
                            progress(stages[index + 1], "running")
                return final

            final_state = asyncio.run(run_with_progress())

        if final_state.get("cdg_document"):
            doc = final_state["cdg_document"]
            # Merge A5 migration_plan (with priority_queue) into the CDGDocument.
            # A5 stores its plan in state["migration_plan"] separately; the CDGDocument
            # built by A4 has only total_vulnerable_assets and no priority_queue.
            a5_plan = final_state.get("migration_plan")
            if a5_plan is not None:
                doc = doc.model_copy(update={"migration_plan": a5_plan})
            final_state["cdg_document"] = doc
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(doc.model_dump(mode="json"), f, indent=2, default=str)
            if verbose:
                print(f"[pipeline] CDG written -> {output_path}")

        if report_path and final_state.get("report_md"):
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(final_state["report_md"])
            if verbose:
                print(f"[pipeline] Report written -> {report_path}")

        return final_state


    @staticmethod
    def _make_validated_node(agent_run, agent_name: str):
        """Wrap an agent.run() coroutine with post-write state validation.

        Returns an async function suitable for graph.add_node().
        After the agent writes to state, validate_state() checks critical
        fields for type correctness. Failures raise with the agent name
        in the message for easy attribution.
        """
        async def _validated(state: CDGState) -> CDGState:
            result = await agent_run(state)
            validate_state(result, agent_name)
            return result
        return _validated


def build_pipeline(config: CryptoDependConfig) -> CryptoDependPipeline:
    """Factory function used by the CLI."""
    return CryptoDependPipeline(config)
