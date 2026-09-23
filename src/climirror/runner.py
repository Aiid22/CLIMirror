"""Resumable firmware orchestration around three bounded LangChain agents."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .agents.localization import LocalizationAgent
from .agents.recovery import RecoveryAgent
from .agents.verification import VerificationAgent
from .config import Config
from .elf_symbols import ELFSymbolIndex
from .export import write_workbook
from .firmware import FirmwareBinary, safe_firmware_name, scan_elf_files, validate_firmware_root
from .ida_client import DatabaseSession, MCPIDAClient
from .llm import AgentRuntime
from .models import AcceptedMapping, FileRunRecord, Rejection, stable_id


LOG = logging.getLogger("climirror")


def _save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    os.replace(temporary, path)


def _fingerprint(root: Path, config: Config, binaries: list[FirmwareBinary]) -> str:
    public = config.model_dump(mode="json")
    public["llm"].pop("api_key", None)
    document = {
        "root": str(root),
        "settings": public,
        "binaries": [(item.relative_path, item.sha256) for item in binaries],
    }
    return hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()[:20]


def prepare_run(root: Path, config: Config) -> tuple[Path, list[FirmwareBinary], list[tuple[str, str]]]:
    root = validate_firmware_root(root)
    if config.run.output_dir.resolve().is_relative_to(root) or config.run.run_dir.resolve().is_relative_to(root):
        raise ValueError("Output and run directories must be outside the input firmware tree")
    config.run.output_dir.mkdir(parents=True, exist_ok=True)
    config.run.run_dir.mkdir(parents=True, exist_ok=True)
    probe = config.run.output_dir / ".climirror-write-check"
    probe.write_text("", encoding="utf-8")
    probe.unlink()
    binaries, skipped = scan_elf_files(root, config.run.max_file_bytes)
    run_dir = config.run.run_dir / f"{safe_firmware_name(root)}-{stable_id(str(root))}" / _fingerprint(root, config, binaries)
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir, binaries, skipped


def _copy_binary(binary: FirmwareBinary, work_root: Path) -> Path:
    destination = (work_root / Path(binary.relative_path)).resolve()
    if not destination.is_relative_to(work_root.resolve()):
        raise ValueError(f"Unsafe firmware relative path: {binary.relative_path}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.is_file() or destination.stat().st_size != binary.size:
        shutil.copy2(binary.absolute_path, destination)
    return destination


async def run_firmware(
    root: Path,
    config: Config,
    ida: MCPIDAClient,
    runtime: AgentRuntime,
    *,
    prepared: tuple[Path, list[FirmwareBinary], list[tuple[str, str]]] | None = None,
) -> tuple[Path, dict[str, Any]]:
    root = validate_firmware_root(root)
    run_dir, binaries, skipped = prepared or prepare_run(root, config)
    events = run_dir / "events.jsonl"

    def log_event(event: str, **values: object) -> None:
        record = {"time_utc": datetime.now(timezone.utc).isoformat(), "event": event, **values}
        with events.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        LOG.info("%s %s", event, json.dumps(values, ensure_ascii=False, default=str))

    records = {item.relative_path: FileRunRecord(relative_path=item.relative_path, status="pending") for item in binaries}
    copied: dict[str, Path] = {}
    sessions: dict[str, DatabaseSession] = {}
    mappings: list[AcceptedMapping] = []
    negatives: list[Rejection] = []
    try:
        for binary in binaries:
            try:
                private_path = _copy_binary(binary, run_dir / "firmware")
                copied[binary.relative_path] = private_path
                sessions[binary.relative_path] = await ida.open_database(private_path, binary.relative_path)
                log_event("database_opened", file=binary.relative_path, database=sessions[binary.relative_path].database)
            except Exception as exc:
                records[binary.relative_path].status = "error"
                records[binary.relative_path].reason = f"{type(exc).__name__}: {str(exc)[:300]}"
                log_event("file_error", file=binary.relative_path, reason=records[binary.relative_path].reason)

        symbol_index = ELFSymbolIndex((path, copied[path]) for path in copied)
        allowed_cross_symbols: set[tuple[str, str, str]] = set()
        cross_context: dict[str, list[dict[str, Any]]] = {path: [] for path in copied}
        for source in copied:
            for candidate in symbol_index.candidates_for(source):
                target_session = sessions.get(candidate.target_path)
                if target_session is None:
                    continue
                try:
                    observation = await ida.invoke_readonly(
                        target_session, "lookup_funcs", {"queries": [candidate.symbol]}
                    )
                except Exception as exc:
                    log_event("cross_library_probe_failed", file=source, symbol=candidate.symbol, reason=str(exc)[:200])
                    continue
                allowed_cross_symbols.add((source, candidate.target_path, candidate.symbol))
                cross_context[source].append({
                    "source_path": source,
                    "target_path": candidate.target_path,
                    "exact_unique_symbol": candidate.symbol,
                    "dynsym_value_hint": candidate.target_address,
                    "target_lookup_evidence_id": observation.id,
                    "target_lookup_result": observation.result,
                })

        localizer = LocalizationAgent(runtime, config.run)
        recovery = RecoveryAgent(runtime)
        checker = VerificationAgent(runtime, ida, ida.ledger, allowed_cross_symbols)

        for binary in binaries:
            relative_path = binary.relative_path
            record = records[relative_path]
            session = sessions.get(relative_path)
            if session is None:
                continue
            result_cache = run_dir / "results" / f"{stable_id(relative_path)}.json"
            if result_cache.is_file():
                try:
                    cached = json.loads(result_cache.read_text(encoding="utf-8"))
                    cached_record = FileRunRecord.model_validate(cached["record"])
                    if cached_record.status == "completed":
                        mappings.extend(AcceptedMapping.model_validate(item) for item in cached["mappings"])
                        negatives.extend(Rejection.model_validate(item) for item in cached.get("rejections", []))
                        records[relative_path] = cached_record
                        log_event("file_resumed", file=relative_path, accepted=cached_record.accepted)
                        continue
                except (ValueError, KeyError, TypeError):
                    log_event("cache_invalid", file=relative_path)

            file_mappings: list[AcceptedMapping] = []
            file_rejections: list[Rejection] = []
            try:
                packages = await localizer.locate(
                    session, ida.ledger, cross_library_candidates=cross_context.get(relative_path, [])
                )
                record.packages = len(packages)
                for package in packages:
                    attempted: set[tuple[Any, ...]] = set()
                    for feedback_round in range(config.agents.max_feedback_rounds + 1):
                        candidates = await recovery.recover(package, negatives)
                        if not candidates:
                            break
                        new_failure = False
                        for candidate in candidates:
                            signature = (
                                candidate.command,
                                candidate.handler_key,
                                tuple(candidate.token_evidence_ids),
                                tuple(candidate.link_ids),
                            )
                            if signature in attempted:
                                continue
                            attempted.add(signature)
                            outcome = await checker.verify(package, candidate, session)
                            if isinstance(outcome, AcceptedMapping):
                                file_mappings.append(outcome)
                                log_event("mapping_accepted", file=relative_path, command=outcome.command, handler=outcome.handler.key)
                            else:
                                file_rejections.append(outcome)
                                negatives.append(outcome)
                                new_failure = True
                                log_event("mapping_rejected", file=relative_path, command=candidate.command,
                                          checks=outcome.failed_checks, round=feedback_round)
                        if not new_failure:
                            break
                record.status = "completed"
                record.accepted = len(file_mappings)
                record.rejected = len(file_rejections)
                mappings.extend(file_mappings)
                _save_json(result_cache, {
                    "record": record.model_dump(),
                    "mappings": [item.model_dump() for item in file_mappings],
                    "rejections": [item.model_dump() for item in file_rejections],
                })
                log_event("file_completed", file=relative_path, packages=record.packages,
                          accepted=record.accepted, rejected=record.rejected)
            except Exception as exc:
                record.status = "error"
                record.reason = f"{type(exc).__name__}: {str(exc)[:300]}"
                log_event("file_error", file=relative_path, reason=record.reason)
    finally:
        await ida.close_all()

    output = config.run.output_dir / f"{safe_firmware_name(root)}.xlsx"
    exported = write_workbook(output, mappings)
    summary: dict[str, Any] = {
        "firmware": str(root),
        "output": str(output),
        "exported": exported,
        "files": [item.model_dump() for item in records.values()],
        "scan_skipped": skipped,
        "run_dir": str(run_dir),
    }
    _save_json(run_dir / "summary.json", summary)
    log_event("run_completed", output=str(output), exported=exported, empty=exported == 0)
    return output, summary

