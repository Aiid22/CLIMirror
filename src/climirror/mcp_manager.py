"""Lifecycle management for mrexodia's loopback idalib-mcp supervisor."""

from __future__ import annotations

import asyncio
import os
import signal
import time
from pathlib import Path
from typing import Any

from .config import Config


class MCPServiceManager:
    """Reuse a valid supervisor or start and later stop one owned process."""

    START_COMMAND = ("uv", "run", "idalib-mcp", "--host", "127.0.0.1", "--port", "13337")

    def __init__(self, config: Config, log_dir: Path):
        self.config = config
        self.log_dir = log_dir
        self.owned = False
        self.process: asyncio.subprocess.Process | None = None
        self.client: Any = None
        self.session: Any = None
        self._session_context: Any = None
        self.tools: dict[str, Any] = {}
        self._log_stream: Any = None

    async def __aenter__(self) -> "MCPServiceManager":
        await self.start()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    async def _port_open(self) -> bool:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", 13337), timeout=0.7)
            del reader
            writer.close()
            await writer.wait_closed()
            return True
        except (OSError, asyncio.TimeoutError):
            return False

    async def _disconnect(self) -> None:
        if self._session_context is not None:
            try:
                await self._session_context.__aexit__(None, None, None)
            finally:
                self._session_context = None
        self.session = None
        self.client = None
        self.tools = {}

    async def _protocol_probe(self) -> None:
        """Perform initialize, tools/list, and idb_list through the MCP adapter."""
        await self._disconnect()
        from langchain_mcp_adapters.client import MultiServerMCPClient
        from langchain_mcp_adapters.tools import load_mcp_tools

        self.client = MultiServerMCPClient({
            "ida": {
                "transport": "http",
                "url": self.config.mcp.url,
                "timeout": self.config.mcp.request_timeout_seconds,
            }
        })
        self._session_context = self.client.session("ida")
        self.session = await asyncio.wait_for(
            self._session_context.__aenter__(), timeout=min(30, self.config.mcp.request_timeout_seconds)
        )
        listed = await asyncio.wait_for(
            load_mcp_tools(self.session), timeout=min(30, self.config.mcp.request_timeout_seconds)
        )
        self.tools = {tool.name: tool for tool in listed}
        if "idb_list" not in self.tools or "idb_open" not in self.tools or "idb_close" not in self.tools:
            raise RuntimeError("Endpoint is MCP but does not expose idb_list/idb_open/idb_close")
        await asyncio.wait_for(self.tools["idb_list"].ainvoke({}), timeout=min(30, self.config.mcp.request_timeout_seconds))

    def _log_tail(self, limit: int = 4000) -> str:
        path = self.log_dir / "idalib-mcp.log"
        if not path.is_file():
            return "(no supervisor log)"
        return path.read_text(encoding="utf-8", errors="replace")[-limit:]

    async def start(self) -> None:
        try:
            await self._protocol_probe()
            self.owned = False
            return
        except Exception as first_error:
            await self._disconnect()
            if await self._port_open():
                raise RuntimeError(
                    "Port 127.0.0.1:13337 is occupied but is not a valid idalib-mcp service"
                ) from first_error

        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._log_stream = (self.log_dir / "idalib-mcp.log").open("ab", buffering=0)
        environment = os.environ.copy()
        environment["IDADIR"] = str(self.config.ida.install_dir)
        self.process = await asyncio.create_subprocess_exec(
            *self.START_COMMAND,
            cwd=str(Path(__file__).resolve().parents[2]),
            env=environment,
            stdout=self._log_stream,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        self.owned = True
        deadline = time.monotonic() + self.config.mcp.startup_timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if self.process.returncode is not None:
                break
            try:
                await self._protocol_probe()
                return
            except Exception as exc:
                last_error = exc
                await self._disconnect()
                await asyncio.sleep(0.5)
        await self._terminate_owned()
        reason = f" ({type(last_error).__name__}: {last_error})" if last_error else ""
        tail = self._log_tail()
        if self._log_stream is not None:
            self._log_stream.close()
            self._log_stream = None
        raise RuntimeError(f"idalib-mcp did not become healthy within {self.config.mcp.startup_timeout_seconds}s{reason}\nLog tail:\n{tail}")

    async def _terminate_owned(self) -> None:
        process = self.process
        if process is None or process.returncode is not None:
            return
        os.killpg(process.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except asyncio.TimeoutError:
            os.killpg(process.pid, signal.SIGKILL)
            await process.wait()

    async def close(self) -> None:
        await self._disconnect()
        if self.owned:
            await self._terminate_owned()
        if self._log_stream is not None:
            self._log_stream.close()
            self._log_stream = None

