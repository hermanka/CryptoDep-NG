"""Agent 2 — Crypto Detection Agent (PRD Section 5.2).

Responsibility:
  Identify all cryptographic usages: library imports, API calls, algorithm constants,
  key generation patterns, certificate loading, protocol configurations.
  Hybrid: Semgrep rule-based scan first, then LLM semantic validation for low-confidence findings.

Acceptance criteria (M2):
  AC-A2-01: Precision >= 0.85, Recall >= 0.80 on CryptoFinding detection
  AC-A2-02: LLM escalation rate < 30% of total findings
  AC-A2-03: Zero false negatives on RSA, ECDSA, DH, ECC algorithm families
  AC-A2-04: Confidence score calibration: stated 0.9 => actual precision >= 0.88
"""
from __future__ import annotations

import json
import pathlib
import re as _re
import time
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader

from cryptodep.agents import BaseAgent
from cryptodep.state import CDGState, CryptoFinding
from cryptodep.tools.llm_tools import build_cpg_slice, call_llm
from cryptodep.tools.semgrep_tools import parse_semgrep_findings, run_semgrep


def _strip_json_fences(text: str) -> str:
    """Strip leading/trailing markdown code fences from LLM output."""
    text = text.strip()
    text = _re.sub(r"^```(?:json)?\s*", "", text)
    text = _re.sub(r"\s*```$", "", text)
    return text.strip()


#: Semgrep rule files (absolute paths resolved from this module) — register new rules here
_RULES_DIR = pathlib.Path(__file__).parent.parent / "rules"
RULE_PATHS: list[str] = [
    str(_RULES_DIR / "crypto-java.yaml"),
    str(_RULES_DIR / "crypto-python.yaml"),
    str(_RULES_DIR / "crypto-javascript.yaml"),
    str(_RULES_DIR / "crypto-java-spring.yaml"),
    str(_RULES_DIR / "crypto-java-spring-vault.yaml"),
]

_PROMPTS_DIR = pathlib.Path(__file__).parent.parent / "prompts"
_JINJA_ENV = Environment(loader=FileSystemLoader(str(_PROMPTS_DIR)), autoescape=False)


def _render_a2_prompt(
    file_path: str, start_line: int, end_line: int, code_slice: str
) -> tuple[str, str]:
    """Render a2_detection.jinja2 → (system_prompt, user_message)."""
    template = _JINJA_ENV.get_template("a2_detection.jinja2")
    module = template.make_module({
        "file_path": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "code_slice": code_slice,
    })
    return str(module.SYSTEM).strip(), str(module.USER).strip()


class CryptoDetectionAgent(BaseAgent):
    agent_name = "A2:CryptoDetection"

    async def run(self, state: CDGState) -> CDGState:
        config = state["config"]
        t0 = time.monotonic()
        self.log.info("detection_start", files=len(state["file_index"]))

        file_paths = list(state["file_index"].keys())

        # ── Step 1: Semgrep scan ──────────────────────────────────────────
        raw_semgrep = run_semgrep(RULE_PATHS, file_paths)
        raw_findings = parse_semgrep_findings(raw_semgrep)

        # ── Step 2: Partition by confidence threshold ─────────────────────
        threshold = config.llm_confidence_threshold
        high_conf = [f for f in raw_findings if f["confidence"] >= threshold]
        to_escalate = [f for f in raw_findings if f["confidence"] < threshold]

        # ── Step 3: LLM escalation for low-confidence findings ────────────
        # Deduplicate by algorithm_family: resolve once per unique family and
        # apply the decision to all findings of that family.  This prevents
        # O(N) LLM calls when the same pattern (e.g., Cipher.getInstance(alg))
        # appears in hundreds of files.
        # Cap: never exceed max_escalation_calls per pipeline run.
        llm_promoted: List[CryptoFinding] = []
        errors = list(state.get("errors", []))
        llm_tokens_used = 0
        max_calls = getattr(config, "max_escalation_calls", 50)

        # Group by algorithm_family; keep insertion order (most confident first).
        family_groups: Dict[str, List[CryptoFinding]] = {}
        for f in to_escalate:
            fam = f.get("algorithm_family", "UNKNOWN")
            family_groups.setdefault(fam, []).append(f)

        calls_made = 0
        for index, (family, group_findings) in enumerate(family_groups.items(), 1):
            if calls_made >= max_calls:
                self.log.warning(
                    "a2_escalation_cap_reached",
                    cap=max_calls,
                    remaining_families=len(family_groups) - calls_made,
                )
                break

            # Use the highest-confidence finding in the group as representative.
            representative = max(group_findings, key=lambda f: f["confidence"])
            self.log.info("a2_llm_escalation", family=family, findings=len(group_findings),
                          call=index, families=len(family_groups))
            try:
                source_ref = representative["source_ref"]
                parts = source_ref.rsplit(":L", 1)
                fpath = parts[0]
                center_line = int(parts[1]) if len(parts) > 1 else 1
                center_line = max(1, center_line)

                code_slice = build_cpg_slice(
                    state["ast_cache"], fpath, center_line, config.max_file_tokens
                )
                if not code_slice:
                    continue

                slice_line_count = code_slice.count("\n") + 1
                end_line = center_line + slice_line_count // 2

                system_prompt, user_msg = _render_a2_prompt(
                    fpath, center_line, end_line, code_slice
                )
                messages = [{"role": "user", "content": user_msg}]
                response = await call_llm(config, messages, system_prompt)
                llm_tokens_used += len(user_msg) // 4 + len(response) // 4
                calls_made += 1

                data = json.loads(_strip_json_fences(response))
                if isinstance(data, dict):
                    # Models sometimes return one finding, or wrap the array as {"findings": [...]}.
                    data = data.get("findings", [data])
                llm_findings: List[Dict[str, Any]] = [f for f in data if isinstance(f, dict)] if isinstance(data, list) else []
                for lf in llm_findings:
                    # Promote the representative finding with LLM-enriched info.
                    # Other group members receive the same algorithm_family decision.
                    promoted: CryptoFinding = {
                        "algorithm_family": lf.get("algorithm_family", family),
                        "parameter_set": lf.get("parameter_set"),
                        "use_context": lf.get("use_context", "other"),
                        "source_ref": lf.get("source_ref", representative["source_ref"]),
                        "confidence": float(lf.get("confidence", 0.80)),
                        "evidence": lf.get("evidence", representative["evidence"]),
                        "detected_by": "hybrid",
                    }
                    llm_promoted.append(promoted)

            except Exception as exc:
                self.log.warning(
                    "llm_escalation_failed",
                    family=family,
                    finding=representative["source_ref"],
                    error=str(exc),
                )
                errors.append({
                    "agent": self.agent_name,
                    "error_type": "llm_escalation_failed",
                    "message": str(exc),
                    "recoverable": True,
                })

        validated_findings = high_conf + llm_promoted

        elapsed = time.monotonic() - t0
        timings = dict(state.get("agent_timings", {}))
        timings[self.agent_name] = elapsed

        self.log.info(
            "detection_complete",
            raw=len(raw_findings),
            validated=len(validated_findings),
            escalated=len(to_escalate),
            elapsed=round(elapsed, 2),
        )

        state.update({
            "raw_crypto_findings": raw_findings,
            "validated_findings": validated_findings,
            "agent_timings": timings,
            "errors": errors,
            "total_llm_tokens": state.get("total_llm_tokens", 0) + llm_tokens_used,
        })
        return state
