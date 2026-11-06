"""BaseAgent abstract class — all CryptoDep-LLM agents inherit from this.

Convention (PRD Section 12):
- Each agent implements `async def run(self, state: CDGState) -> CDGState`
- All LLM calls go through `cryptodep.tools.llm_tools`, never directly
- Use `state.update({...})` for mutations, never reassign the state object
- Log with structlog, never print()
"""
from __future__ import annotations

from abc import ABC, abstractmethod

import structlog

from cryptodep.config import CryptoDependConfig
from cryptodep.state import CDGState


class BaseAgent(ABC):
    """Abstract base for all five CryptoDep-LLM agents."""

    #: Override in subclass to set structured log context
    agent_name: str = "base"

    def __init__(self, config: CryptoDependConfig) -> None:
        self.config = config
        self.log = structlog.get_logger().bind(agent_name=self.agent_name)

    @abstractmethod
    async def run(self, state: CDGState) -> CDGState:
        """Execute this agent's pipeline step.

        Args:
            state: Current CDGState from the LangGraph orchestrator.

        Returns:
            Updated CDGState with this agent's outputs populated.
        """
        raise NotImplementedError
