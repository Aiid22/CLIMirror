"""LangChain agent runtime with Pydantic structured output."""

from __future__ import annotations

import json
from typing import Any, Protocol, Sequence, TypeVar

from pydantic import BaseModel

from .config import AgentConfig, LLMConfig
from .models import CheckJudgment, LocalizationResult, RecoveryResponse


T = TypeVar("T", bound=BaseModel)


class AgentRuntime(Protocol):
    async def run(
        self,
        *,
        agent_name: str,
        system_prompt: str,
        payload: dict[str, Any],
        response_type: type[T],
        tools: Sequence[Any] = (),
    ) -> T: ...


class LangChainAgentRuntime:
    """Creates a fresh bounded LangChain graph for each role invocation."""

    def __init__(self, llm: LLMConfig, agents: AgentConfig):
        try:
            from langchain_deepseek import ChatDeepSeek
        except ImportError as exc:  # pragma: no cover - exercised by install preflight
            raise RuntimeError("LangChain dependencies are missing; run `uv sync --locked`") from exc
        self.settings = agents
        self.model = ChatDeepSeek(
            model=llm.model,
            api_key=llm.api_key,
            api_base=llm.base_url,
            temperature=llm.temperature,
            max_tokens=llm.max_output_tokens,
            timeout=llm.timeout_seconds,
            max_retries=llm.max_retries,
        )

    async def run(
        self,
        *,
        agent_name: str,
        system_prompt: str,
        payload: dict[str, Any],
        response_type: type[T],
        tools: Sequence[Any] = (),
    ) -> T:
        from langchain.agents import create_agent
        from langchain.agents.structured_output import ToolStrategy

        graph = create_agent(
            model=self.model,
            tools=list(tools),
            system_prompt=system_prompt,
            response_format=ToolStrategy(response_type),
            name=agent_name,
        )
        state = await graph.ainvoke(
            {"messages": [{"role": "user", "content": json.dumps(payload, ensure_ascii=False, default=str)}]},
            config={"recursion_limit": self.settings.max_steps},
        )
        structured = state.get("structured_response")
        if structured is None:
            raise RuntimeError(f"{agent_name} returned no structured_response")
        return structured if isinstance(structured, response_type) else response_type.model_validate(structured)


class OfflineAgentRuntime:
    """No-network smoke runtime. It exports nothing unless a test supplies seed data."""

    async def run(
        self,
        *,
        agent_name: str,
        system_prompt: str,
        payload: dict[str, Any],
        response_type: type[T],
        tools: Sequence[Any] = (),
    ) -> T:
        if response_type is LocalizationResult:
            value: Any = {"packages": payload.get("seed_packages", []), "evidence_rationale": "offline seed evidence only"}
        elif response_type is RecoveryResponse:
            value = {"candidates": payload.get("seed_candidates", [])}
        elif response_type is CheckJudgment:
            passed = {"passed": True, "evidence_ids": payload.get("evidence_ids", []), "evidence_rationale": "deterministic gates passed"}
            value = {"command": passed, "handler": passed, "structure": passed, "traceability": passed, "accepted": True, "evidence_rationale": "offline deterministic verification"}
        else:
            raise ValueError(f"Unsupported response type: {response_type.__name__}")
        return response_type.model_validate(value)

