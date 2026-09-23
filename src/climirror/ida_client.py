"""Session-bound, read-only adapter for the idalib-mcp HTTP supervisor."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import Field, create_model
from pydantic_core import PydanticUndefined

from .config import Config
from .evidence import EvidenceLedger, result_hash
from .mcp_manager import MCPServiceManager
from .models import EvidenceObservation


READ_ONLY_TOOLS = frozenset({
    "server_health", "entity_query", "find_regex", "lookup_funcs", "imports_query",
    "xrefs_to", "callees", "callers", "basic_blocks", "decompile", "disasm",
    "callgraph", "get_string", "get_bytes", "get_int", "get_global_value", "int_convert",
})


def _normalize_result(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    if isinstance(value, list):
        return [_normalize_result(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalize_result(item) for key, item in value.items()}
    return value


def _find_database_id(value: Any) -> str | None:
    value = _normalize_result(value)
    if isinstance(value, dict):
        for key in ("database", "session_id", "id"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate:
                return candidate
        for item in value.values():
            found = _find_database_id(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = _find_database_id(item)
            if found:
                return found
    if isinstance(value, str):
        match = re.search(r"(?:database|session)(?:_id)?[\"' :=]+([A-Za-z0-9_.:-]+)", value, re.I)
        if match:
            return match.group(1)
        stripped = value.strip().strip('"\'')
        if re.fullmatch(r"[A-Za-z0-9_.:-]{4,128}", stripped):
            return stripped
        return None
    return None


@dataclass(frozen=True)
class DatabaseSession:
    database: str
    binary_path: str
    copied_path: Path
    tools: tuple[Any, ...]


class MCPIDAClient:
    def __init__(self, config: Config, manager: MCPServiceManager, ledger: EvidenceLedger):
        self.config = config
        self.manager = manager
        self.ledger = ledger
        self.sessions: dict[str, DatabaseSession] = {}
        self._by_binary: dict[str, str] = {}

    def _tool(self, name: str) -> Any:
        try:
            return self.manager.tools[name]
        except KeyError:
            raise RuntimeError(f"idalib-mcp does not expose required tool: {name}") from None

    async def _call(self, name: str, arguments: dict[str, Any]) -> Any:
        result = await asyncio.wait_for(
            self._tool(name).ainvoke(arguments), timeout=self.config.mcp.request_timeout_seconds
        )
        return _normalize_result(result)

    async def open_database(self, copied_path: Path, relative_path: str) -> DatabaseSession:
        copied_path = copied_path.resolve(strict=True)
        response = await self._call("idb_open", {
            "path": str(copied_path),
            "mode": "force_headless",
            "run_auto_analysis": True,
            "build_caches": True,
            "init_hexrays": True,
        })
        database = _find_database_id(response)
        if not database:
            raise RuntimeError(f"idb_open returned no database session ID: {str(response)[:500]}")
        session = DatabaseSession(database, relative_path, copied_path, ())
        tools = tuple(self._bound_tools(session))
        session = DatabaseSession(database, relative_path, copied_path, tools)
        self.sessions[database] = session
        self._by_binary[relative_path] = database
        try:
            # idb_open(init_hexrays=true) plus this worker query is the effective
            # license/processor/decompiler preflight for the file's architecture.
            await self.invoke_readonly(session, "server_health", {})
        except Exception:
            await self.close_database(database)
            raise
        return session

    def session_for_binary(self, relative_path: str) -> DatabaseSession:
        database = self._by_binary.get(relative_path)
        if database is None:
            raise ValueError(f"No open IDA session for {relative_path}")
        return self.sessions[database]

    async def close_database(self, database: str) -> None:
        session = self.sessions.pop(database, None)
        if session is None:
            return
        self._by_binary.pop(session.binary_path, None)
        await self._call("idb_close", {"database": database, "save": False})

    async def close_all(self) -> None:
        for database in list(self.sessions):
            try:
                await self.close_database(database)
            except Exception:
                # Closing the remaining sessions is more important than masking the run result.
                continue

    async def invoke_readonly(
        self, session: DatabaseSession, tool_name: str, arguments: dict[str, Any]
    ) -> EvidenceObservation:
        if tool_name not in READ_ONLY_TOOLS:
            raise ValueError(f"Tool is not on the read-only allowlist: {tool_name}")
        result = await self._call(tool_name, {**arguments, "database": session.database})
        return self.ledger.record(
            session_id=session.database,
            binary_path=session.binary_path,
            tool=tool_name,
            arguments=arguments,
            result=result,
        )

    async def requery(self, observation: EvidenceObservation) -> bool:
        session = self.sessions.get(observation.session_id)
        if session is None:
            return False
        result = await self._call(
            observation.tool, {**observation.arguments, "database": observation.session_id}
        )
        return result_hash(result) == observation.result_sha256

    def _bound_tools(self, session: DatabaseSession) -> list[Any]:
        from langchain_core.tools import StructuredTool

        wrapped: list[Any] = []
        for name in sorted(READ_ONLY_TOOLS):
            inner = self.manager.tools.get(name)
            if inner is None:
                continue
            schema = getattr(inner, "args_schema", None)
            fields: dict[str, tuple[Any, Any]] = {}
            if schema is not None:
                for field_name, field in schema.model_fields.items():
                    if field_name == "database":
                        continue
                    annotation = field.annotation or Any
                    if field.is_required():
                        default: Any = Field(description=field.description)
                    else:
                        value = field.default if field.default is not PydanticUndefined else None
                        default = Field(default=value, description=field.description)
                    fields[field_name] = (annotation, default)
            args_schema = create_model(f"{name.title().replace('_', '')}Arguments", **fields)

            async def call_bound(_name: str = name, **kwargs: Any) -> dict[str, Any]:
                observation = await self.invoke_readonly(session, _name, kwargs)
                return {"evidence_id": observation.id, "result": observation.result}

            wrapped.append(StructuredTool.from_function(
                coroutine=call_bound,
                name=name,
                description=(getattr(inner, "description", "") or f"Read-only IDA query: {name}")
                    + " The database session is injected by CLIMirror. Cite the returned evidence_id.",
                args_schema=args_schema,
            ))
        return wrapped

