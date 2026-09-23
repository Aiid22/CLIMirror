"""Validated contracts exchanged by CLIMirror's three agents."""

from __future__ import annotations

import hashlib
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def stable_id(*parts: object) -> str:
    data = "\x1f".join(str(part) for part in parts).encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()[:16]


def ea(value: int) -> str:
    return f"0x{value:x}"


class EvidenceObservation(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    session_id: str
    binary_path: str
    tool: str
    arguments: dict[str, Any]
    result: Any
    result_sha256: str


class TokenEvidence(BaseModel):
    id: str
    text: str
    address: int = Field(ge=0)
    reference: int = Field(ge=0)
    observation_ids: list[str] = Field(min_length=1)


class HandlerEvidence(BaseModel):
    key: str
    address: int = Field(ge=0)
    name: str = Field(min_length=1)
    auto_name: bool
    relative_path: str = Field(min_length=1)
    observation_ids: list[str] = Field(min_length=1)


class EvidenceLink(BaseModel):
    id: str
    kind: Literal["branch", "pointer_table", "registration", "cross_library"]
    token_address: int = Field(ge=0)
    token_ref: int = Field(ge=0)
    dispatch_address: int = Field(ge=0)
    handler_address: int = Field(ge=0)
    handler_file: str
    relation_address: int = Field(ge=0)
    proof_addresses: list[int] = Field(default_factory=list)
    import_name: str = ""
    import_address: int = Field(default=0, ge=0)
    observation_ids: list[str] = Field(min_length=1)


class EvidencePackage(BaseModel):
    id: str
    binary_path: str
    dispatch_address: int = Field(ge=0)
    tokens: list[TokenEvidence] = Field(min_length=1)
    handlers: list[HandlerEvidence] = Field(min_length=1)
    links: list[EvidenceLink] = Field(min_length=1)
    ledger_evidence_ids: list[str] = Field(min_length=1)
    evidence_rationale: str = Field(default="", max_length=1200)


class LocalizationResult(BaseModel):
    packages: list[EvidencePackage] = Field(default_factory=list)
    evidence_rationale: str = Field(default="", max_length=1200)


class MappingCandidate(BaseModel):
    command: str = Field(min_length=1, max_length=1000)
    handler_key: str
    token_evidence_ids: list[str] = Field(min_length=1, max_length=32)
    link_ids: list[str] = Field(min_length=1, max_length=32)
    evidence_rationale: str = Field(default="", max_length=1200)

    @field_validator("command")
    @classmethod
    def no_control_chars(cls, value: str) -> str:
        if any(ord(char) < 32 for char in value):
            raise ValueError("Command contains control characters")
        return " ".join(value.split())


class RecoveryResponse(BaseModel):
    candidates: list[MappingCandidate] = Field(default_factory=list)


CheckName = Literal["command", "handler", "structure", "traceability"]


class CheckResult(BaseModel):
    passed: bool
    evidence_ids: list[str] = Field(default_factory=list)
    evidence_rationale: str = Field(default="", max_length=800)


class CheckJudgment(BaseModel):
    command: CheckResult
    handler: CheckResult
    structure: CheckResult
    traceability: CheckResult
    accepted: bool
    evidence_rationale: str = Field(default="", max_length=1200)

    @model_validator(mode="after")
    def acceptance_matches_checks(self) -> "CheckJudgment":
        expected = all((self.command.passed, self.handler.passed, self.structure.passed, self.traceability.passed))
        if self.accepted != expected:
            raise ValueError("accepted must equal the conjunction of all four checks")
        return self

    @property
    def failed_checks(self) -> list[CheckName]:
        return [name for name in ("command", "handler", "structure", "traceability") if not getattr(self, name).passed]


class Rejection(BaseModel):
    package_id: str
    candidate: MappingCandidate
    failed_checks: list[CheckName]
    evidence_rationale: str


class AcceptedMapping(BaseModel):
    command: str
    handler: HandlerEvidence
    package_id: str
    token_evidence_ids: list[str]
    link_ids: list[str]
    evidence_chain: str

    def identity(self) -> tuple[str, str, int]:
        return self.command, self.handler.relative_path, self.handler.address


class FileRunRecord(BaseModel):
    relative_path: str
    status: Literal["pending", "skipped", "error", "completed"]
    reason: str = ""
    packages: int = 0
    accepted: int = 0
    rejected: int = 0

