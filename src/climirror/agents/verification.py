"""Adversarial agent plus deterministic final evidence gates."""

from __future__ import annotations

from typing import Iterable

from ..evidence import EvidenceLedger
from ..ida_client import DatabaseSession, MCPIDAClient
from ..llm import AgentRuntime
from ..models import AcceptedMapping, CheckJudgment, EvidencePackage, MappingCandidate, Rejection, ea


PROMPT = r"""
ROLE
You are CLIMirror's adversarial evidence auditor. Seek a concrete counterexample
to each mapping. Acceptance is allowed only after four independent checks.

INPUT, TOOLS, AND OUTPUT
The user message contains one immutable package, candidate, and deterministic
re-query status. Use only the available read-only IDA tools; the database session
is injected. Return CheckJudgment with command, handler, structure, traceability,
accepted, and short evidence_rationale fields. Each passed check cites ledger IDs.
You cannot override a deterministic failure.

FOUR CHECKS
1. command: every literal word exists at its claimed string address/xref.
2. handler: the selected function is the demonstrated target; cross-library cases
   require a unique exact `.dynsym` match and source call relation.
3. structure: token order, branch/menu hierarchy, alias and placeholders match.
4. traceability: the full token -> xref -> dispatch/table/registration -> relation
   -> handler chain can be replayed from evidence.

PRIVATE DELIBERATION
Privately use observation -> candidate -> counterexample -> evidence check ->
conclusion for each check. Do not expose full chain of thought. Output only short,
reproducible evidence summaries.

FEW-SHOT ACCEPT
EV-s proves "status"; EV-x proves its xref; EV-b proves a conditional basic-block
path to callsite; EV-c proves the call target H1. All re-query hashes match. Mark
all four checks passed and cite the appropriate EV IDs.

FEW-SHOT REJECT 1
A pointer-table string entry is proven but the adjacent function pointer resolves
to H2 while the candidate selects H1. handler and traceability fail.

FEW-SHOT REJECT 2
The evidence proves ordered tokens "show ip", while the candidate says "ip show",
or adds an unevidenced "detail" placeholder. command/structure fail. Also reject
a cross-library target selected by a non-unique export name.

SELF-CHECK
Before submission verify every cited ID exists in the supplied ledger or a tool
result, accepted equals the conjunction of all four checks, and no conclusion is
based on names or proximity alone. Never output code or hidden reasoning.
"""


class VerificationAgent:
    def __init__(
        self,
        runtime: AgentRuntime,
        ida: MCPIDAClient,
        ledger: EvidenceLedger,
        allowed_cross_symbols: set[tuple[str, str, str]],
    ):
        self.runtime = runtime
        self.ida = ida
        self.ledger = ledger
        self.allowed_cross_symbols = allowed_cross_symbols

    @staticmethod
    def _rejection(package: EvidencePackage, candidate: MappingCandidate, failed: Iterable[str], rationale: str) -> Rejection:
        return Rejection(
            package_id=package.id,
            candidate=candidate,
            failed_checks=sorted(set(failed)),
            evidence_rationale=rationale,
        )

    async def verify(
        self, package: EvidencePackage, candidate: MappingCandidate, session: DatabaseSession
    ) -> AcceptedMapping | Rejection:
        failed: list[str] = []
        tokens = {item.id: item for item in package.tokens}
        links = {item.id: item for item in package.links}
        handlers = {item.key: item for item in package.handlers}
        handler = handlers.get(candidate.handler_key)
        selected_tokens = [tokens.get(item) for item in candidate.token_evidence_ids]
        selected_links = [links.get(item) for item in candidate.link_ids]

        if len(set(candidate.token_evidence_ids)) != len(candidate.token_evidence_ids) or not all(selected_tokens):
            failed.append("command")
        if handler is None or len(set(candidate.link_ids)) != len(candidate.link_ids) or not all(selected_links):
            failed.append("handler")
        if not failed:
            actual = " ".join(item.text.strip() for item in selected_tokens if item)
            if actual != candidate.command:
                failed.append("command")
            references = [item.reference for item in selected_tokens if item]
            if references != sorted(references):
                failed.append("structure")
            for token in selected_tokens:
                if not any(
                    link.token_address == token.address
                    and link.token_ref == token.reference
                    and link.handler_address == handler.address
                    and link.handler_file == handler.relative_path
                    for link in selected_links
                ):
                    failed.append("traceability")
                    break
            if any(
                link.dispatch_address != package.dispatch_address
                or link.handler_address != handler.address
                or link.handler_file != handler.relative_path
                for link in selected_links
            ):
                failed.append("handler")
            if any(
                link.kind == "cross_library"
                and (package.binary_path, link.handler_file, link.import_name) not in self.allowed_cross_symbols
                for link in selected_links
            ):
                failed.extend(("handler", "traceability"))
            if any(
                (link.handler_file != package.binary_path) != (link.kind == "cross_library")
                for link in selected_links
            ):
                failed.extend(("handler", "traceability"))
        if failed:
            return self._rejection(package, candidate, failed, "Candidate IDs, literals, order, or handler relation do not match the immutable package")

        cited = set()
        for item in selected_tokens:
            cited.update(item.observation_ids)
        cited.update(handler.observation_ids)
        for item in selected_links:
            cited.update(item.observation_ids)
        try:
            observations = self.ledger.require(cited)
        except ValueError as exc:
            return self._rejection(package, candidate, ["traceability"], str(exc))
        for observation in observations:
            try:
                if not await self.ida.requery(observation):
                    failed.append("traceability")
                    break
            except Exception as exc:
                return self._rejection(package, candidate, ["traceability"], f"MCP re-query failed: {type(exc).__name__}: {str(exc)[:160]}")
        if failed:
            return self._rejection(package, candidate, failed, "At least one cited MCP observation changed during deterministic re-query")

        judgment = await self.runtime.run(
            agent_name="climirror_verification",
            system_prompt=PROMPT,
            payload={
                "package": package.model_dump(),
                "candidate": candidate.model_dump(),
                "deterministic_requery": "all cited observation hashes matched",
                "evidence_ids": sorted(cited),
                "output_contract": CheckJudgment.model_json_schema(),
            },
            response_type=CheckJudgment,
            tools=session.tools,
        )
        try:
            for name in ("command", "handler", "structure", "traceability"):
                check = getattr(judgment, name)
                if check.passed and not check.evidence_ids:
                    raise ValueError(f"{name} passed without evidence IDs")
                self.ledger.require(check.evidence_ids)
        except ValueError as exc:
            return self._rejection(package, candidate, ["traceability"], f"Verifier cited invalid evidence: {exc}")
        if not judgment.accepted:
            return self._rejection(package, candidate, judgment.failed_checks, judgment.evidence_rationale)

        token_chain = ", ".join(
            f"{item.text!r}@{ea(item.address)}/xref {ea(item.reference)} [{','.join(item.observation_ids)}]"
            for item in selected_tokens
        )
        link_chain = ", ".join(
            f"{item.kind}:{ea(item.dispatch_address)}->{ea(item.relation_address)}->{item.handler_file}:{ea(item.handler_address)} [{','.join(item.observation_ids)}]"
            for item in selected_links
        )
        checks = "; ".join(
            f"{name}=pass({getattr(judgment, name).evidence_rationale})"
            for name in ("command", "handler", "structure", "traceability")
        )
        return AcceptedMapping(
            command=candidate.command,
            handler=handler,
            package_id=package.id,
            token_evidence_ids=candidate.token_evidence_ids,
            link_ids=candidate.link_ids,
            evidence_chain=f"tokens: {token_chain} | links: {link_chain} | handler: {handler.relative_path}:{ea(handler.address)} {handler.name} | checks: {checks}",
        )

