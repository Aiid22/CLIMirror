"""LangChain localization agent."""

from __future__ import annotations

import re
from typing import Any

from ..config import RunConfig
from ..evidence import EvidenceLedger, validate_package_citations
from ..ida_client import DatabaseSession
from ..llm import AgentRuntime
from ..models import EvidenceLink, EvidencePackage, HandlerEvidence, LocalizationResult, TokenEvidence, stable_id


_AUTO_NAME = re.compile(r"^(?:sub_|nullsub_|j_|loc_|FUN_|fcn\.)", re.IGNORECASE)


PROMPT = r"""
ROLE
You are CLIMirror's firmware reverse-engineering localization expert. Work as a
skeptical IDA analyst. Your job is to locate CLI dispatch evidence in one ELF,
not to guess command semantics.

TASK AND INPUT CONTRACT
The user message gives the current binary path and exact unique `.dynsym`
cross-library candidates. Use only the supplied read-only IDA tools. Every tool
result contains an `evidence_id`; copy those IDs into every fact they attest and
into `ledger_evidence_ids`. Produce LocalizationResult only.

TOOL AND EVIDENCE RULES
Use only server_health, entity_query, find_regex, lookup_funcs,
imports_query, xrefs_to, callees, callers, basic_blocks, decompile, disasm,
callgraph, get_string, get_bytes, get_int, get_global_value, and int_convert.
The database argument is injected and must never be supplied. Never propose a
token without string and xref observations. Never propose a handler without a
function observation. A link needs observations supporting token address, xref,
dispatch, relation site, and handler address. A cross_library link additionally
needs the supplied unique exact symbol candidate and source IDA import/call
evidence; name similarity is insufficient. Generated names such as sub_401000
must set auto_name=true. Prefer an empty result to an unsupported package.

PRIVATE DELIBERATION
Privately follow observation -> candidate -> counterexample -> evidence check ->
conclusion. Check conditional alternatives, indirect calls, table stride, and
conflicting xrefs. Do not reveal the full deliberation. Output only the Pydantic
structure and a short, reproducible `evidence_rationale`.

FEW-SHOT ACCEPT
Observation EV-s says "show version" at 0x5000; EV-x shows xref 0x1010 inside
dispatcher 0x1000; EV-c shows a conditional path to call 0x1028; EV-h identifies
function 0x2000 as show_version. Correct: one branch link, token, and handler,
all four EV IDs cited. A pointer table is also acceptable when get_int/get_bytes
prove neighboring string and function entries.

FEW-SHOT REJECT 1
The string "reset" is near a call in decompilation, but xrefs_to and basic_blocks
do not connect it to the call. Reject it; proximity is not a dispatch relation.

FEW-SHOT REJECT 2
main imports cli_apply and two shared libraries export cli_apply. Reject the
cross-library handler because the exact export is not unique. Likewise reject an
alias or handler chosen only from its name.

SELF-CHECK
Before submission verify that every address, name, path, token, relation, and
evidence ID occurs in tool output or the supplied exact cross-library facts.
Do not output code, hidden reasoning, prose outside the structured response, or
facts that require a modifying IDA tool.
"""


class LocalizationAgent:
    def __init__(self, runtime: AgentRuntime, settings: RunConfig):
        self.runtime = runtime
        self.settings = settings

    async def locate(
        self,
        session: DatabaseSession,
        ledger: EvidenceLedger,
        *,
        cross_library_candidates: list[dict[str, Any]],
    ) -> list[EvidencePackage]:
        response = await self.runtime.run(
            agent_name="climirror_localization",
            system_prompt=PROMPT,
            payload={
                "current_binary": session.binary_path,
                "cross_library_candidates": cross_library_candidates,
                "output_contract": LocalizationResult.model_json_schema(),
                "maximum_packages": self.settings.max_evidence_packages_per_binary,
            },
            response_type=LocalizationResult,
            tools=session.tools,
        )
        packages: list[EvidencePackage] = []
        for raw in response.packages[: self.settings.max_evidence_packages_per_binary]:
            if raw.binary_path != session.binary_path:
                continue
            tokens = [TokenEvidence(
                id=stable_id(raw.binary_path, item.text, item.address, item.reference, *item.observation_ids),
                text=item.text, address=item.address, reference=item.reference,
                observation_ids=item.observation_ids,
            ) for item in raw.tokens]
            handlers = [HandlerEvidence(
                key=stable_id(item.relative_path, item.address, item.name),
                address=item.address, name=item.name,
                auto_name=item.auto_name or bool(_AUTO_NAME.match(item.name)),
                relative_path=item.relative_path, observation_ids=item.observation_ids,
            ) for item in raw.handlers]
            links = [EvidenceLink(
                id=stable_id(raw.binary_path, item.kind, item.token_address, item.token_ref,
                             item.dispatch_address, item.handler_file, item.handler_address,
                             item.relation_address, *item.observation_ids),
                **item.model_dump(exclude={"id"}),
            ) for item in raw.links]
            package = EvidencePackage(
                id=stable_id(raw.binary_path, raw.dispatch_address,
                             *(item.id for item in links), *(item.key for item in handlers)),
                binary_path=raw.binary_path,
                dispatch_address=raw.dispatch_address,
                tokens=tokens,
                handlers=handlers,
                links=links,
                ledger_evidence_ids=raw.ledger_evidence_ids,
                evidence_rationale=raw.evidence_rationale,
            )
            try:
                validate_package_citations(package, ledger)
            except ValueError:
                continue
            packages.append(package)
        return packages

