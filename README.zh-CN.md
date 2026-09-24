# CLIMirror

[English](README.md) | **简体中文**

本仓库包含我们在论文中使用的 CLIMirror 实现。我们用它从已经解包的嵌入式固件中恢复 CLI 命令与处理函数的对应关系。检查阶段会通过 IDA 重放每一条导出映射所引用的证据。

程序接收一个解包固件目录的绝对路径，递归查找其中的 ELF 可执行文件和共享库，通过 IDA Pro 分析后，生成一个以固件目录命名的 Excel 文件。工作簿固定包含四列：

- `Command`
- `Handler Address and Name`
- `Handler Relative Path`
- `Evidence Chain`

handler 地址采用 IDA 报告的有效地址。对于 `sub_401000` 这类 IDA 自动生成的函数名，我们会写成 `[IDA auto] sub_401000`，避免把它误认为固件中的原始符号。所有 Excel 单元格都按文本写入，因此以 `=`、`+`、`-` 或 `@` 开头的命令不会被当成公式执行。

## 运行环境

论文实现运行在以下环境：

- Ubuntu 24.04
- Python 3.12
- `uv`
- IDA Pro 9.1 Professional
- 与固件架构匹配且已授权的 Hex-Rays decompiler

默认的 IDA 安装目录是 `/opt/idapro-9.1`。运行 CLIMirror 前，需要为 `uv` 使用的 Python 完成 idalib 激活，并确认当前用户可以正常使用 IDA 许可证。论文实现分析 ARM 和 MIPS ELF 固件。

## 安装

进入项目目录后执行：

```bash
uv sync --locked
cp config.example.toml config.toml
chmod 600 config.toml
```

打开 `config.toml`，确认 IDA 路径并填写 DeepSeek API key：

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

`config.toml` 不会进入版本控制。实现只从这个本地文件读取 API key，不会把密钥写入运行日志、证据记录或导出的工作簿。

## 运行

`--firmware` 后面需要提供解包固件目录的绝对路径：

```bash
uv run climirror --firmware /absolute/path/to/unpacked-firmware
```

默认输出位置为：

```text
output/<固件目录名>.xlsx
```

如果某个 ELF 无法完成分析，我们会记录错误并继续处理其他文件。如果没有映射通过检查，程序仍会生成带有四列表头的工作簿。这样可以明确区分“结果为空”和“任务没有运行完成”。

## IDA MCP 服务

我们使用 mrexodia 的 `idalib-mcp`，并固定连接本机地址：

```text
http://127.0.0.1:13337/mcp
```

启动时，CLIMirror 会初始化 MCP 连接、读取工具列表并调用 `idb_list`。如果服务已经正常运行，我们直接复用；如果连接被拒绝且 13337 端口空闲，CLIMirror 会以无 shell 参数方式启动：

```bash
uv run idalib-mcp --host 127.0.0.1 --port 13337
```

如果端口被不兼容的程序占用，我们会直接报错，不会结束未知进程，也不会在同一端口启动第二个 supervisor。

每个 ELF 都会先复制到当前运行目录，再交给 IDA 打开。因此，IDA 数据库和缓存会出现在私有副本旁边，而不会写入解包固件目录。后续工具调用所需的 `database` session ID 由包装器自动注入，语言模型无法填写或替换这个字段。

运行结束时，我们使用 `idb_close(save=false)` 关闭本次打开的数据库。只有当 supervisor 是由 CLIMirror 自动启动时，我们才会结束该进程；运行前已经存在的服务会继续保留。

## 三个 Agent

三个角色都通过 LangChain `create_agent` 构建，并使用 Pydantic 约束结构化输出。

**定位 Agent** 扮演固件逆向分析人员，查询字符串、交叉引用、控制流、调用关系、注册位置和函数指针表。它只能使用包装器提供的只读 IDA 工具。每一次观察都会先获得证据 ID，之后才能被 Agent 引用。

**恢复 Agent** 从定位阶段的证据包中恢复完整且有序的命令。它不能直接调用 IDA，也不能使用证据包之外的命令词元、别名、参数占位符或 handler。

**检查 Agent** 采用对抗式审计角色，分别检查命令存在性、handler 来源、命令结构和端到端可追溯性。最终决定仍由外层确定性检查作出。缺少命令字面量、handler 没有来源、词元顺序错误或证据无法重放时，模型的接受意见不会覆盖这些失败。

被拒绝的候选会作为结构化负样本返回恢复 Agent。每个证据包最多反馈两轮；如果同一个失败候选再次出现，我们会停止继续尝试。

Agent 只能使用下面这些只读工具：

```text
server_health, entity_query, find_regex, lookup_funcs, imports_query,
xrefs_to, callees, callers, basic_blocks, decompile, disasm, callgraph,
get_string, get_bytes, get_int, get_global_value, int_convert
```

我们不会向 Agent 暴露数据库修改、补丁、重命名、任意 Python 执行、调试器控制或数据库保存工具。

三个 Agent 的完整提示词分别保存在：

- `src/climirror/agents/localization.py`
- `src/climirror/agents/recovery.py`
- `src/climirror/agents/verification.py`

提示词包含角色、输入约束、证据规则、正确案例和拒绝案例。我们要求模型在内部检查观察、候选、反例和证据一致性，但持久化的内容只有结构化结论和简短的 `evidence_rationale`，不会保存或导出模型的完整私有思维过程。

## 证据与跨库映射

每次 MCP 查询都会写入追加式 Evidence Ledger。记录中包含 IDA 数据库 session、工具名称、参数、结果哈希和稳定证据 ID。Agent 只能引用 Ledger 中已经存在的 ID。检查阶段会重新执行所有被引用的查询，并比较新结果和原始结果的哈希。证据缺失、结果变化或无法重放时，该映射不会导出。

对于跨共享库映射，我们使用 `pyelftools` 读取 `.dynsym`。只有当一个导入名称在固件中存在唯一且完全一致的导出，并且 IDA 中的 import、调用关系和目标函数也相互吻合时，我们才接受这个跨库候选。近似名称、重复导出和仅靠语义相似度选择的目标都会被拒绝。

## 运行记录与边界

运行数据保存在 `runs/` 下，包括私有 ELF 副本、Evidence Ledger、逐文件状态、已完成结果、MCP 日志和最终汇总。固件内容和非敏感配置没有变化时，运行器会复用已经完成的文件结果。

CLIMirror 是一个静态分析系统。只有依次通过定位、恢复、确定性检查和证据重放的映射才会写入工作簿。`Evidence Chain` 记录每一行结果被接受时使用的静态证据，并提供返回对应 IDA 分析位置的路径。

主要依赖包括 `langchain`、`langchain-deepseek`、`langchain-mcp-adapters`、`ida-pro-mcp`、`pydantic`、`pyelftools` 和 `openpyxl`。具体版本以及固定的 `ida-pro-mcp` Git revision 记录在 `uv.lock` 中。

