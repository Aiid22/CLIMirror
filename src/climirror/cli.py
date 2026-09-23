"""Ubuntu command-line entry point."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
from pathlib import Path

from .config import load_config, preflight
from .evidence import EvidenceLedger
from .firmware import validate_firmware_root
from .ida_client import MCPIDAClient
from .llm import LangChainAgentRuntime, OfflineAgentRuntime
from .mcp_manager import MCPServiceManager
from .runner import prepare_run, run_firmware


def main() -> None:
    parser = argparse.ArgumentParser(prog="climirror", description="Recover firmware CLI command/handler mappings")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[2] / "config.toml")
    parser.add_argument("--firmware", type=Path, required=True, help="Absolute path to unpacked firmware directory")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    try:
        root = validate_firmware_root(args.firmware)
        config = load_config(args.config)
        preflight(config)
        prepared = prepare_run(root, config)
        run_dir = prepared[0]
        runtime = OfflineAgentRuntime() if config.run.offline else LangChainAgentRuntime(config.llm, config.agents)

        async def execute() -> tuple[Path, dict]:
            async with MCPServiceManager(config, run_dir / "mcp") as manager:
                ledger = EvidenceLedger(run_dir / "evidence-ledger.jsonl")
                ida = MCPIDAClient(config, manager, ledger)
                return await run_firmware(root, config, ida, runtime, prepared=prepared)

        output, summary = asyncio.run(execute())
        print(json.dumps({"output": str(output), "exported": summary["exported"], "run_dir": summary["run_dir"]}, ensure_ascii=False))
    except Exception as exc:
        parser.exit(2, f"CLIMirror error: {type(exc).__name__}: {exc}\n")


if __name__ == "__main__":
    main()

