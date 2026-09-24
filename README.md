# CLIMirror

**English** | [简体中文](README.zh-CN.md)

This repository contains the CLIMirror implementation used in our paper. We use it to recover CLI command-to-handler mappings from unpacked embedded firmware. Every exported mapping is tied to evidence that the verification stage replays through IDA.

The input is an absolute path to an unpacked firmware directory. CLIMirror recursively finds ELF executables and shared libraries, analyzes them through IDA Pro, and writes one workbook named after the firmware directory. The workbook contains exactly four columns:

- `Command`
- `Handler Address and Name`
- `Handler Relative Path`
- `Evidence Chain`

Handler addresses are effective addresses reported by IDA. When IDA has generated a function name such as `sub_401000`, we label it as `[IDA auto] sub_401000` instead of presenting it as an original symbol. We also write every Excel cell as text so that a command beginning with `=`, `+`, `-`, or `@` is not interpreted as a formula.

## Environment

The implementation runs in the following environment:

- Ubuntu 24.04
- Python 3.12
- `uv`
- IDA Pro 9.1 Professional
- A licensed Hex-Rays decompiler for the firmware architecture

The default IDA directory is `/opt/idapro-9.1`. Before running CLIMirror, activate idalib for the Python installation used by `uv` and make sure the current user can open IDA without a license prompt. The paper implementation analyzes ARM and MIPS ELF firmware.

## Installation

From the project directory, run:

```bash
uv sync --locked
cp config.example.toml config.toml
chmod 600 config.toml
```

Open `config.toml`, check the IDA path, and add the DeepSeek API key:

```toml
[ida]
install_dir = "/opt/idapro-9.1"

[mcp]
url = "http://127.0.0.1:13337/mcp"
startup_timeout_seconds = 60
request_timeout_seconds = 900

[llm]
base_url = "https://api.deepseek.com"
api_key = "YOUR_API_KEY"
model = "deepseek-v4-pro"
timeout_seconds = 90
max_output_tokens = 2500
temperature = 0.0
max_retries = 2

[agents]
max_steps = 24
max_feedback_rounds = 2
```

We keep `config.toml` out of version control. The implementation reads the API key from this local file and does not include it in run logs, evidence records, or exported workbooks.

## Running CLIMirror

Pass an absolute path to the unpacked firmware directory:

```bash
uv run climirror --firmware /absolute/path/to/unpacked-firmware
```

By default, the result is written to:

```text
output/<firmware-directory-name>.xlsx
```

If one ELF cannot be analyzed, we record the error and continue with the remaining files. If no mapping passes verification, we still create the workbook with its four-column header so that an empty result is explicit rather than confused with a failed run.

## IDA MCP lifecycle

We use mrexodia's `idalib-mcp` supervisor at a fixed loopback endpoint:

```text
http://127.0.0.1:13337/mcp
```

At startup, CLIMirror initializes the MCP connection, lists the available tools, and calls `idb_list`. If a valid service is already running, we reuse it. If the connection is refused and port 13337 is free, CLIMirror starts the following command without passing it through a shell:

```bash
uv run idalib-mcp --host 127.0.0.1 --port 13337
```

If the port is occupied by something that is not a compatible MCP service, we stop with an error. We do not terminate the unknown process or start a second supervisor on the same port.

Before opening an ELF, we copy it into the current run directory. IDA databases and caches are therefore created next to the private copy rather than in the unpacked firmware tree. We open each file with headless analysis and Hex-Rays initialization enabled. Every later tool call receives the corresponding `database` session ID from our wrapper; the language model cannot supply or replace that field.

At the end of the run, we close every database opened by CLIMirror with `idb_close(save=false)`. We terminate the supervisor only when we started it ourselves. A supervisor that existed before the run is left running.

## The three agents

We implement all three roles with LangChain `create_agent` and use Pydantic schemas for their structured responses.

The **localization agent** works as a firmware reverse-engineering analyst. It queries strings, cross-references, control flow, call relations, registration sites, and function-pointer tables. It calls only the read-only IDA tools exposed by our wrapper. Each observation is assigned an evidence ID before the agent cites it.

The **recovery agent** reconstructs complete and ordered commands from a localization package. It has no direct access to IDA. A command token, alias, argument placeholder, or handler is usable only when it already exists in the package.

The **verification agent** takes an adversarial role. It checks command existence, handler provenance, command structure, and end-to-end traceability separately. The outer deterministic verifier then applies the final decision. A model response cannot override a missing literal, an unsupported handler, a token-order mismatch, or a failed evidence replay.

Rejected candidates become structured negative examples for the recovery agent. We allow at most two feedback rounds for a package and stop when the same rejected candidate appears again.

The agents access only this read-only tool set:

```text
server_health, entity_query, find_regex, lookup_funcs, imports_query,
xrefs_to, callees, callers, basic_blocks, decompile, disasm, callgraph,
get_string, get_bytes, get_int, get_global_value, int_convert
```

We do not expose database mutation, patching, renaming, arbitrary Python execution, debugger control, or database-saving tools to the agents.

Each agent keeps its complete prompt in its own source file:

- `src/climirror/agents/localization.py`
- `src/climirror/agents/recovery.py`
- `src/climirror/agents/verification.py`

The prompts include the role, input contract, evidence rules, accepted examples, and rejection examples. We ask the model to examine observations, candidates, counterexamples, and evidence consistency internally. The persisted output contains only the structured conclusion and a short `evidence_rationale`; we do not store or export the model's private chain of thought.

## Evidence and cross-library mappings

We record every MCP observation in an append-only Evidence Ledger. A ledger entry contains the IDA database session, tool name, arguments, result hash, and a stable evidence ID. We accept agent output only when every cited ID is already present in the ledger. During verification, we repeat every cited query and compare its result hash with the original observation. A missing, changed, or unreplayable observation prevents export.

For mappings that cross shared-library boundaries, we read `.dynsym` with `pyelftools`. We accept a cross-library candidate only when an imported name has one unique exact export in the firmware and the IDA-side import, call relation, and target function also agree. We reject approximate name matches, duplicate exports, and targets supported only by semantic similarity.

## Run artifacts and limitations

Run data is stored under `runs/`. It includes private ELF copies, the Evidence Ledger, per-file status, completed results, MCP logs, and a final summary. When the firmware bytes and non-secret settings are unchanged, the runner reuses completed file results.

CLIMirror is a static-analysis pipeline. It exports only mappings for which the localization, recovery, deterministic verification, and evidence-replay stages all succeed. The `Evidence Chain` column records the static evidence used to accept each row and provides the route back to the corresponding IDA analysis.

The main dependencies are `langchain`, `langchain-deepseek`, `langchain-mcp-adapters`, `ida-pro-mcp`, `pydantic`, `pyelftools`, and `openpyxl`. Exact versions, including the pinned `ida-pro-mcp` Git revision, are recorded in `uv.lock`.

