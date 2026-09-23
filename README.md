# CLIMirror

CLIMirror 用来从已经解包的嵌入式固件中恢复 CLI 命令与处理函数之间的对应关系。输入是一个固件目录，程序会递归查找其中的 ELF 可执行文件和共享库，调用 IDA Pro 分析字符串、交叉引用、控制流和函数调用，最后生成一个 Excel 文件。

输出文件只有四列：

- `Command`
- `Handler Address and Name`
- `Handler Relative Path`
- `Evidence Chain`

handler 地址采用 IDA 中的有效地址。像 `sub_401000` 这样的 IDA 自动命名会显示为 `[IDA auto] sub_401000`，避免让人误以为它是固件中的原始符号。Excel 单元格统一按文本写入，因此以 `=`、`+` 等字符开头的命令不会被当成公式执行。

## 环境

项目面向以下环境：

- Ubuntu 24.04
- Python 3.12
- `uv`
- IDA Pro 9.1 Professional
- 与固件架构匹配的 Hex-Rays decompiler

IDA 默认安装在 `/opt/idapro-9.1`。运行前需要完成 idalib 激活，并保证当前用户能够正常使用 IDA 许可证。CLIMirror 主要面向 ARM 和 MIPS 固件，但没有在代码中硬编码架构限制。

## 安装

进入项目目录后执行：

```bash
uv sync --locked
cp config.example.toml config.toml
chmod 600 config.toml
```

然后编辑 `config.toml`。通常只需要确认 IDA 路径并填写 DeepSeek API key：

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

`config.toml` 已加入 `.gitignore`。程序只从这个文件读取 API key，不会把密钥写入日志、证据文件或 Excel。

## 使用

`--firmware` 必须是解包固件目录的绝对路径：

```bash
uv run climirror --firmware /absolute/path/to/unpacked-firmware
```

默认输出位置是：

```text
output/<固件目录名>.xlsx
```

如果没有找到通过检查的映射，程序仍会生成 Excel，只是文件中只有表头。某个 ELF 分析失败时，其错误会写入运行记录，其他文件会继续处理。

## IDA MCP 服务

CLIMirror 使用 mrexodia 的 `idalib-mcp`，地址固定为：

```text
http://127.0.0.1:13337/mcp
```

程序启动时会先检查这个地址是否是有效的 MCP 服务。如果服务已经存在，就直接复用；如果连接被拒绝并且端口空闲，程序会启动：

```bash
uv run idalib-mcp --host 127.0.0.1 --port 13337
```

如果 13337 端口被其他程序占用，CLIMirror 会直接报错，不会结束未知进程，也不会尝试启动第二个服务。

每个 ELF 都会先复制到本次运行目录，再通过 `idb_open` 打开。这样 IDA 产生的数据库和缓存不会写入原始固件目录。每个 IDA 工具调用都会自动携带对应的 `database` session ID，模型无法自行填写或修改它。分析结束后，程序使用 `idb_close(save=false)` 关闭本次创建的数据库会话。

如果 MCP 服务是 CLIMirror 自动启动的，任务结束后会一并关闭；如果服务在运行前已经存在，只关闭本次数据库会话，保留原有服务。

## 三个 Agent 如何协作

三个角色都使用 LangChain `create_agent` 构建，并使用 Pydantic 结构化输出。

定位 Agent 负责在当前 ELF 中寻找可能的 CLI 字符串、xref、分派函数、函数指针表和注册关系。它可以调用只读 IDA MCP 工具，并把每次查询记录到 Evidence Ledger。

恢复 Agent 根据定位阶段生成的证据包恢复完整命令。它不能调用 IDA，也不能选择证据包之外的 handler、命令词元或证据编号。

检查 Agent 会重新查询底层证据，分别检查命令是否真实存在、handler 来源是否可靠、词元顺序是否一致，以及整条关系是否可以追溯。任何确定性检查失败都会否决结果。失败案例会以结构化负样本返回恢复 Agent，最多反馈两轮；重复失败的候选不会继续尝试。

Agent 能使用的 IDA 工具被限制为只读白名单：

```text
server_health, entity_query, find_regex, lookup_funcs, imports_query,
xrefs_to, callees, callers, basic_blocks, decompile, disasm, callgraph,
get_string, get_bytes, get_int, get_global_value, int_convert
```

修改数据库、执行 Python、调试和保存数据库一类的工具不会暴露给 Agent。

三个提示词分别保存在：

- `src/climirror/agents/localization.py`
- `src/climirror/agents/recovery.py`
- `src/climirror/agents/verification.py`

提示词包含角色设定、正确示例、拒绝示例和内部核对步骤。模型只返回结构化结果和简短的 `evidence_rationale`，不会把完整内部推理写入运行记录或 Excel。

## 证据与跨库分析

每次 MCP 查询都会进入 Evidence Ledger，记录数据库 session、工具名称、参数、结果哈希和稳定证据 ID。Agent 只能引用已经存在的证据 ID。检查阶段会再次执行被引用的查询，并比较结果哈希；重查失败或结果发生变化时，该映射不会导出。

跨共享库映射使用 `pyelftools` 读取 `.dynsym`。只有导入名称与某一个共享库的导出名称完全一致，并且 IDA 中的调用关系和目标函数查询也通过时，才会建立跨库映射。存在同名的多个导出、模糊名称匹配或缺少调用关系时，候选会被拒绝。

## 运行记录

每次运行的数据保存在 `runs/` 下，其中包括固件副本、Evidence Ledger、逐文件状态、已完成结果、MCP 日志和最终汇总。相同固件和相同非敏感配置再次运行时，可以复用已经完成的文件结果。

CLIMirror 的目标是尽量减少缺少证据的误报，但静态分析仍然可能漏掉运行时生成的命令、加密字符串、复杂间接调用或 IDA 无法正确恢复的控制流。因此，Excel 中的 Evidence Chain 应当作为后续人工复核的入口，而不是对固件行为的绝对证明。

主要依赖包括 `langchain`、`langchain-deepseek`、`langchain-mcp-adapters`、`ida-pro-mcp`、`pydantic`、`pyelftools` 和 `openpyxl`。具体版本和 `ida-pro-mcp` Git 提交记录在 `uv.lock` 中。

