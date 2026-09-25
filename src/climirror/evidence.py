"""Append-only evidence ledger for MCP observations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

from .models import EvidenceObservation, stable_id


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def result_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _scalars(value: Any) -> Iterable[Any]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _scalars(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _scalars(item)
    else:
        yield value


class EvidenceLedger:
    """Records immutable observations and validates every agent citation."""

    def __init__(self, path: Path | None = None):
        self.path = path
        self._items: dict[str, EvidenceObservation] = {}
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        session_id: str,
        binary_path: str,
        tool: str,
        arguments: dict[str, Any],
        result: Any,
    ) -> EvidenceObservation:
        clean_arguments = {key: value for key, value in arguments.items() if key != "database"}
        digest = result_hash(result)
        # Stable for the lifetime of an IDA database session and unambiguous if
        # the same binary is reopened later in a resumed run.
        evidence_id = "EV-" + stable_id(session_id, binary_path, tool, canonical_json(clean_arguments), digest)
        item = EvidenceObservation(
            id=evidence_id,
            session_id=session_id,
            binary_path=binary_path,
            tool=tool,
            arguments=clean_arguments,
            result=result,
            result_sha256=digest,
        )
        existing = self._items.get(evidence_id)
        if existing is not None and existing != item:
            raise RuntimeError(f"Evidence ID collision: {evidence_id}")
        if existing is None:
            self._items[evidence_id] = item
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(item.model_dump_json() + "\n")
        return item

    def get(self, evidence_id: str) -> EvidenceObservation:
        try:
            return self._items[evidence_id]
        except KeyError:
            raise ValueError(f"Unknown evidence ID: {evidence_id}") from None

    def require(self, evidence_ids: Iterable[str], *, binary_path: str | None = None) -> list[EvidenceObservation]:
        ids = list(evidence_ids)
        if not ids or len(ids) != len(set(ids)):
            raise ValueError("Evidence IDs must be non-empty and unique")
        items = [self.get(item) for item in ids]
        if binary_path is not None and any(item.binary_path != binary_path for item in items):
            raise ValueError("Evidence belongs to a different binary")
        return items

    def attests(self, evidence_ids: Iterable[str], *required_values: Any) -> bool:
        values: list[Any] = []
        for item in self.require(evidence_ids):
            values.extend(_scalars(item.result))
        normalized = {str(value).strip().lower() for value in values if value is not None}
        for required in required_values:
            variants = {str(required).strip().lower()}
            if isinstance(required, int):
                variants.add(f"0x{required:x}")
            if not variants.intersection(normalized):
                return False
        return True


def validate_package_citations(package: Any, ledger: EvidenceLedger) -> None:
    """Reject fabricated IDs and facts before recovery sees a package."""
    package_ids = set(package.ledger_evidence_ids)
    ledger.require(package_ids)
    cited: set[str] = set()
    for token in package.tokens:
        ledger.require(token.observation_ids)
        cited.update(token.observation_ids)
        if not ledger.attests(token.observation_ids, token.text, token.address, token.reference):
            raise ValueError(f"Token {token.id} is not attested by its observations")
    for handler in package.handlers:
        ledger.require(handler.observation_ids)
        cited.update(handler.observation_ids)
        if not ledger.attests(handler.observation_ids, handler.address, handler.name):
            raise ValueError(f"Handler {handler.key} is not attested by its observations")
    for link in package.links:
        ledger.require(link.observation_ids)
        cited.update(link.observation_ids)
        required = (link.token_address, link.token_ref, link.dispatch_address, link.handler_address, link.relation_address)
        if not ledger.attests(link.observation_ids, *required):
            raise ValueError(f"Link {link.id} is not fully attested by its observations")
    if not cited.issubset(package_ids):
        raise ValueError("Package ledger_evidence_ids omits cited observations")

