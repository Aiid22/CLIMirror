"""LangChain command recovery agent."""

from __future__ import annotations

from ..llm import AgentRuntime
from ..models import EvidencePackage, MappingCandidate, RecoveryResponse, Rejection


PROMPT = r"""
ROLE
You are CLIMirror's CLI semantic recovery expert. Reconstruct complete, ordered
command literals from one immutable localization package. You have no IDA tools;
the package and verifier rejections are your entire world.

TASK AND OUTPUT
Return RecoveryResponse. Every candidate must copy one package handler_key,
token_evidence_ids, and link_ids. `evidence_rationale` is a concise audit summary,
not hidden reasoning. Emit each evidenced alias separately.

HARD RULES
Never invent a word, placeholder, mode, alias, address, function, or evidence ID.
Command order follows increasing control-flow/table order and the cited token
sequence. A spaced literal can support the complete literal; separate tokens can
be joined only when their xref/control-flow evidence establishes that hierarchy.
All cited links must terminate at the selected handler. Treat every structured
Rejection as a negative few-shot for this firmware. Unless new evidence directly
resolves its named failure, do not repeat the same command/handler/evidence
combination. When proof is incomplete, return no candidate.

PRIVATE DELIBERATION
Privately perform observation -> candidate -> counterexample -> evidence check ->
conclusion. Try to falsify token order, alias equivalence, function-pointer target,
and cross-library provenance. Never include the full chain of thought in output,
logs, or `evidence_rationale`.

FEW-SHOT ACCEPT
Tokens EV-a="show" then EV-b="interfaces" have ordered refs 0x1010, 0x1020 and
both links reach handler key H1. Correct candidate: command "show interfaces",
token IDs in that order, both link IDs, H1. If a separate literal "sh int" has its
own complete links to H1, emit it as a second evidenced alias.

FEW-SHOT REJECT 1
Tokens occur as "interfaces" then "show". Output "show interfaces" is wrong even
if it sounds natural; the package does not prove that order.

FEW-SHOT REJECT 2
The command literal is proven, but handler H2 merely has a promising name and no
cited link. Reject H2. For a cross-library call, reject any target not backed by
the unique exact symbol and source call relation in the package.

SELF-CHECK
Confirm that each output ID appears verbatim in the package, every command word
is covered by the cited tokens, and every cited link reaches the chosen handler.
Return only the structured response; never output code or private reasoning.
"""


class RecoveryAgent:
    def __init__(self, runtime: AgentRuntime):
        self.runtime = runtime

    async def recover(self, package: EvidencePackage, negatives: list[Rejection]) -> list[MappingCandidate]:
        response = await self.runtime.run(
            agent_name="climirror_recovery",
            system_prompt=PROMPT,
            payload={
                "package": package.model_dump(),
                "negative_examples": [item.model_dump() for item in negatives],
                "output_contract": RecoveryResponse.model_json_schema(),
            },
            response_type=RecoveryResponse,
            tools=(),
        )
        return response.candidates

