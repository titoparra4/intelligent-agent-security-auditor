"""Static Python adapter (AST only - the audited code is never imported or executed).

Detection support (partial by design, see ``coverage``):

* OpenAI Agents SDK: ``Agent(name=, instructions=, tools=, handoffs=, model=)``, ``@function_tool``,
  ``Runner.run*(..., max_turns=)``, ``agent.as_tool(...)``.
* LangChain: ``@tool``, ``Tool(...)`` / ``StructuredTool.from_function``, ``AgentExecutor(max_iterations=)``,
  ``load_tools([...])``, Python REPL / shell tools, vector stores.
* LangGraph: ``create_react_agent(model, tools, interrupt_before=)``, ``recursion_limit``.
* CrewAI: ``Agent(role=, tools=, allow_delegation=, allow_code_execution=, max_iter=)``, ``Crew(agents=)``.
* AutoGen: ``AssistantAgent`` / ``UserProxyAgent`` / ``ConversableAgent``, ``code_execution_config``,
  ``human_input_mode``, ``max_consecutive_auto_reply``, ``GroupChat``; local vs Docker executors.
* Custom code: tool function bodies are analysed for HTTP egress, e-mail, file deletion/writes,
  subprocess/exec, SQL verbs, OAuth scope constants and approval-gate calls.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any

from agent_security_auditor.core.classify import (
    classify_host,
    infer_data_access,
    infer_operations,
    is_documentation_url,
    scope_info,
    sensitivity_for,
)
from agent_security_auditor.core.context import AuditContext
from agent_security_auditor.core.parsing import call_name, kwarg, literal, module_constants
from agent_security_auditor.core.redaction import redact
from agent_security_auditor.models.inventory import (
    Agent,
    CodeExecutionSite,
    Delegation,
    MemoryStore,
    NetworkDestination,
    Tool,
)

FRAMEWORK_IMPORTS = {
    "agents": "openai-agents",
    "langchain": "langchain",
    "langchain_core": "langchain",
    "langchain_community": "langchain",
    "langchain_openai": "langchain",
    "langchain_experimental": "langchain",
    "langgraph": "langgraph",
    "crewai": "crewai",
    "crewai_tools": "crewai",
    "autogen": "autogen",
    "autogen_agentchat": "autogen",
    "autogen_ext": "autogen",
    "pyautogen": "autogen",
    "llama_index": "llamaindex",
    "pydantic_ai": "pydantic-ai",
    "smolagents": "smolagents",
    "anthropic": "anthropic-sdk",
    "openai": "openai-sdk",
}
AGENT_CTORS = {"Agent", "AssistantAgent", "UserProxyAgent", "ConversableAgent", "CodeAgent", "ToolCallingAgent",
               "ReActAgent", "FunctionAgent", "SocietyOfMindAgent", "CodeExecutorAgent"}
AGENT_FACTORIES = {"create_react_agent", "create_tool_calling_agent", "create_openai_tools_agent",
                   "initialize_agent", "AgentExecutor", "create_openai_functions_agent"}
CODE_EXEC_TOOLS = {
    "PythonREPLTool": ("python_repl", False), "PythonAstREPLTool": ("python_repl", False),
    "PythonREPL": ("python_repl", False), "ShellTool": ("shell", False), "BashProcess": ("shell", False),
    "TerminalTool": ("shell", False), "CodeInterpreterTool": ("python_repl", None),
    "LocalCommandLineCodeExecutor": ("autogen_executor", False),
    "DockerCommandLineCodeExecutor": ("docker", True), "JupyterCodeExecutor": ("python_repl", False),
    "E2BSandbox": ("remote_sandbox", True), "CodeInterpreter": ("python_repl", None),
}
LOAD_TOOLS_EXEC = {"terminal": "shell", "python_repl": "python_repl", "shell": "shell"}
LOAD_TOOLS_NET = {"requests_all", "requests_post", "requests_put", "requests_delete", "requests_patch"}
VECTOR_STORES = {"Chroma", "FAISS", "PGVector", "Pinecone", "PineconeVectorStore", "Qdrant", "QdrantVectorStore",
                 "Weaviate", "WeaviateVectorStore", "Milvus", "LanceDB", "ElasticsearchStore", "MongoDBAtlasVectorSearch",
                 "Redis", "OpenSearchVectorSearch"}
MEMORY_CLASSES = {"ConversationBufferMemory": "short_term", "ConversationSummaryMemory": "short_term",
                  "ConversationBufferWindowMemory": "short_term", "VectorStoreRetrieverMemory": "long_term",
                  "Memory": "long_term", "MemoryClient": "long_term", "InMemorySaver": "short_term",
                  "MemorySaver": "short_term", "SqliteSaver": "long_term", "PostgresSaver": "long_term",
                  "InMemoryStore": "long_term", "ZepMemory": "long_term"}
HTTP_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE",
                "request": None, "urlopen": None, "stream": None, "head": "HEAD"}
HTTP_CLIENT_ROOTS = ("requests", "httpx", "aiohttp", "session", "client", "urllib", "http", "urllib3", "self.session",
                     "self.client", "sess")
APPROVAL_CALL = re.compile(r"(?i)(approv|confirm|human_in_the_loop|ask_human|ask_user|require_human|interrupt|consent)")
SQL_VERBS = re.compile(r"(?i)^\s*(select|insert|update|delete|drop|truncate|alter|grant|create)\b")
UNTRUSTED_VAR = re.compile(r"(?i)(email|mail|body|content|document|doc|page|html|input|message|msg|query|text|"
                           r"data|memory|memories|context|history|result|output|retrieved|chunk|ticket)")
URL_RE = re.compile(r"https?://[^\s\"'<>)\]}]+")


@dataclass
class _FuncFacts:
    operations: set[str] = field(default_factory=set)
    data_access: set[str] = field(default_factory=set)
    destinations: list[tuple[str, int, str | None, bool]] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    identity: str | None = None
    approval_call: bool = False
    exec_sites: list[tuple[str, int]] = field(default_factory=list)


class PythonCodeAdapter:
    name = "python-ast"
    coverage = (
        "Partial, static detection for OpenAI Agents SDK, LangChain, LangGraph, CrewAI and AutoGen plus generic "
        "tool-body analysis. Tools/agents created dynamically (factories, loops, config-driven registries), "
        "decorators re-exported under other names and cross-module dataflow are NOT resolved."
    )

    def applies(self, ctx: AuditContext) -> bool:
        return bool(ctx.discovery.by_kind("python"))

    def populate(self, ctx: AuditContext) -> None:
        for f, tree in ctx.python_trees():
            try:
                self._file(ctx, f.rel, f.text(), tree)
            except RecursionError:
                ctx.parse_errors.append({"file": f.rel, "error": "python: AST too deep to analyse"})

    # ------------------------------------------------------------------------------------
    def _file(self, ctx: AuditContext, rel: str, text: str, tree: ast.Module) -> None:
        inv = ctx.inventory
        imports = _imports(tree)
        frameworks = sorted({FRAMEWORK_IMPORTS[m.split(".")[0]] for m in imports if m.split(".")[0] in FRAMEWORK_IMPORTS})
        for fw in frameworks:
            if fw not in inv.frameworks:
                inv.frameworks.append(fw)
        is_mcp_server = any(m == "mcp" or m.startswith("mcp.") or m.startswith("fastmcp") for m in imports)
        consts = module_constants(tree)
        funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}

        # --- decorated tools -------------------------------------------------------------
        tool_funcs: dict[str, str] = {}  # function name -> tool name
        for fn in funcs.values():
            for dec in fn.decorator_list:
                cn = call_name(dec).split(".")[-1].rstrip("()")
                if cn in ("function_tool", "tool") and not (is_mcp_server and "." in call_name(dec)):
                    tname = fn.name
                    if isinstance(dec, ast.Call):
                        override = literal(kwarg(dec, "name_override")) or literal(kwarg(dec, "name"))
                        if dec.args and isinstance(literal(dec.args[0]), str):
                            override = literal(dec.args[0])
                        tname = override or tname
                    tool_funcs[fn.name] = str(tname)
        # Tool(name=..., func=...) / StructuredTool.from_function(func=..., name=...)
        for call in _calls(tree):
            cn = call_name(call).split(".")[-1]
            if cn in ("Tool", "from_function", "StructuredTool"):
                func = kwarg(call, "func") or (call.args[0] if call.args else None)
                tname = literal(kwarg(call, "name"))
                if isinstance(func, ast.Name) and func.id in funcs:
                    tool_funcs[func.id] = str(tname or func.id)

        for fname, tname in tool_funcs.items():
            fn = funcs[fname]
            facts = self._analyse_function(fn, consts)
            desc = ast.get_docstring(fn) or ""
            ops = sorted(facts.operations) or infer_operations(tname, desc)
            data = sorted(facts.data_access | set(infer_data_access(tname, desc)))
            perms = list(dict.fromkeys(facts.scopes))
            tool = Tool(
                name=tname, source=f"code:{frameworks[0] if frameworks else 'python'}", file=rel, line=fn.lineno,
                description=redact(desc.strip().splitlines()[0] if desc.strip() else "") or "",
                operations=ops, data_access=data, sensitivity=sensitivity_for(data), permissions=perms,
                permission_provenance="code" if perms else ("code" if facts.operations else "inferred"),
                identity=facts.identity,
                requires_approval=True if facts.approval_call else None,
                approval_provenance="code" if facts.approval_call else None,
                network_destinations=[d[0] for d in facts.destinations],
            )
            inv.add_tool(tool)
            for url, line, method, carries in facts.destinations:
                self._add_dest(ctx, url, rel, line, method, True, carries)
            for kind, line in facts.exec_sites:
                inv.code_execution.append(CodeExecutionSite(kind, rel, line, False, tname))

        # --- module-wide egress / exec not inside tools ---------------------------------
        tool_lines = {(funcs[f].lineno, funcs[f].end_lineno or funcs[f].lineno) for f in tool_funcs}
        for call in _calls(tree):
            if any(lo <= call.lineno <= hi for lo, hi in tool_lines):
                continue
            dest = _http_call(call, consts)
            if dest:
                self._add_dest(ctx, dest[0], rel, call.lineno, dest[1], True, dest[2])
            ex = _exec_kind(call)
            if ex:
                inv.code_execution.append(CodeExecutionSite(ex, rel, call.lineno, None, None))

        # --- explicit code-execution tools / executors ------------------------------------
        for call in _calls(tree):
            cn = call_name(call).split(".")[-1]
            if cn in CODE_EXEC_TOOLS:
                kind, sandboxed = CODE_EXEC_TOOLS[cn]
                inv.code_execution.append(CodeExecutionSite(kind, rel, call.lineno, sandboxed, cn, f"{cn}()"))
                inv.add_tool(Tool(name=cn, source="code:" + (frameworks[0] if frameworks else "python"), file=rel,
                                  line=call.lineno, operations=["execute"], permission_provenance="code"))
            if cn == "load_tools" and call.args:
                names = literal(call.args[0]) or []
                for n in names if isinstance(names, list) else []:
                    if n in LOAD_TOOLS_EXEC:
                        inv.code_execution.append(CodeExecutionSite(LOAD_TOOLS_EXEC[n], rel, call.lineno, False, n))
                        inv.add_tool(Tool(name=n, source="code:langchain", file=rel, line=call.lineno,
                                          operations=["execute"], permission_provenance="code"))
                    elif n in LOAD_TOOLS_NET:
                        inv.add_tool(Tool(name=n, source="code:langchain", file=rel, line=call.lineno,
                                          operations=["network", "send"], data_access=["web"],
                                          permission_provenance="code"))

        # --- memory / vector stores ------------------------------------------------------
        user_scoped = bool(re.search(r"(?i)\b(user_id|tenant_id|namespace|org_id|account_id)\b", text))
        for call in _calls(tree):
            cn = call_name(call).split(".")[-1]
            if cn in VECTOR_STORES or cn in MEMORY_CLASSES:
                kind = "vector" if cn in VECTOR_STORES else MEMORY_CLASSES[cn]
                if cn == "Memory" and "mem0" not in " ".join(imports):
                    continue
                if cn == "Redis" and "vectorstores" not in " ".join(imports):
                    continue
                coll = literal(kwarg(call, "collection_name")) or literal(kwarg(call, "index_name"))
                inv.memory.append(MemoryStore(
                    name=f"{cn}:{coll}" if coll else cn, kind=kind, file=rel, line=call.lineno,
                    scope="per_user" if user_scoped else "unknown", provenance="code"))

        # --- agents ------------------------------------------------------------------------
        var_to_agent: dict[str, str] = {}
        agent_calls: list[tuple[ast.Call, str | None]] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                tgt = node.targets[0].id if isinstance(node.targets[0], ast.Name) else None
                cn = call_name(node.value).split(".")[-1]
                if cn in AGENT_CTORS or cn in AGENT_FACTORIES:
                    agent_calls.append((node.value, tgt))
        seen = {id(c) for c, _ in agent_calls}
        for call in _calls(tree):
            cn = call_name(call).split(".")[-1]
            if (cn in AGENT_CTORS or cn in AGENT_FACTORIES) and id(call) not in seen:
                agent_calls.append((call, None))

        if not frameworks and agent_calls:
            frameworks = ["custom"]
        for call, var in agent_calls:
            cn = call_name(call).split(".")[-1]
            if cn == "Agent" and not frameworks:
                continue
            agent = self._agent_from_call(ctx, rel, call, var, cn, frameworks, consts, tool_funcs)
            if agent is None:
                continue
            if var:
                var_to_agent[var] = agent.name
            inv.add_agent(agent)

        # resolve handoffs / sub-agents expressed as variable names
        for a in inv.agents:
            if a.file != rel:
                continue
            a.sub_agents = [var_to_agent.get(s, s) for s in a.sub_agents]
            resolved_tools = []
            for t in a.tools:
                if t.startswith("@agent:"):
                    target = var_to_agent.get(t[7:], t[7:])
                    if target not in a.sub_agents:
                        a.sub_agents.append(target)
                    continue
                resolved_tools.append(tool_funcs.get(t, t))
            a.tools = resolved_tools
            for t in a.tools:
                tool = inv.tool(t)
                if tool and a.name not in tool.agents:
                    tool.agents.append(a.name)
            for s in a.sub_agents:
                if not any(d.from_agent == a.name and d.to_agent == s for d in inv.delegations):
                    inv.delegations.append(Delegation(a.name, s, None, None, "in-process", rel, a.line, "code"))

        # max_turns on Runner.run(agent, ...) ; recursion_limit in invoke config
        for call in _calls(tree):
            cn = call_name(call)
            if cn.split(".")[-1] in ("run", "run_sync", "run_streamed") and "Runner" in cn:
                mt = literal(kwarg(call, "max_turns"))
                if call.args and isinstance(call.args[0], ast.Name) and isinstance(mt, int):
                    ag = inv.agent(var_to_agent.get(call.args[0].id, ""))
                    if ag:
                        ag.max_iterations, ag.max_iterations_source = mt, "code"
            if cn.split(".")[-1] in ("invoke", "ainvoke", "stream"):
                cfg = literal(kwarg(call, "config")) or (literal(call.args[1]) if len(call.args) > 1 else None)
                if isinstance(cfg, dict) and isinstance(cfg.get("recursion_limit"), int):
                    for a in inv.agents:
                        if a.file == rel and a.max_iterations is None:
                            a.max_iterations, a.max_iterations_source = cfg["recursion_limit"], "code"

        # CrewAI / AutoGen group delegation
        for call in _calls(tree):
            cn = call_name(call).split(".")[-1]
            if cn in ("Crew", "GroupChat", "RoundRobinGroupChat", "SelectorGroupChat", "Swarm"):
                members = kwarg(call, "agents") or kwarg(call, "participants") or (call.args[0] if call.args else None)
                names = [var_to_agent.get(e.id, e.id) for e in getattr(members, "elts", []) if isinstance(e, ast.Name)]
                for a_name in names:
                    a = inv.agent(a_name)
                    if a is None:
                        continue
                    if cn == "Crew" and a.allow_delegation is not True:
                        continue
                    for b_name in names:
                        if b_name != a_name and not any(d.from_agent == a_name and d.to_agent == b_name for d in inv.delegations):
                            inv.delegations.append(Delegation(a_name, b_name, None, None, cn, rel, call.lineno, "code"))

    # ------------------------------------------------------------------------------------
    def _agent_from_call(self, ctx: AuditContext, rel: str, call: ast.Call, var: str | None, cn: str,
                         frameworks: list[str], consts: dict[str, Any], tool_funcs: dict[str, str]) -> Agent | None:
        fw = frameworks[0] if frameworks else "custom"
        if "crewai" in frameworks and cn == "Agent":
            fw = "crewai"
        elif "openai-agents" in frameworks and cn == "Agent":
            fw = "openai-agents"
        elif cn in ("AssistantAgent", "UserProxyAgent", "ConversableAgent") and "autogen" in frameworks:
            fw = "autogen"
        elif cn in ("create_react_agent",) and "langgraph" in frameworks:
            fw = "langgraph"
        elif cn in AGENT_FACTORIES and "langchain" in frameworks:
            fw = "langchain"
        name = (literal(kwarg(call, "name")) or literal(kwarg(call, "role")) or
                (literal(call.args[0]) if call.args and cn in ("AssistantAgent", "UserProxyAgent", "ConversableAgent") else None)
                or var or f"{cn}@{rel}:{call.lineno}")
        model_node = kwarg(call, "model") or kwarg(call, "llm") or kwarg(call, "model_client")
        if model_node is None and cn == "create_react_agent" and call.args:
            model_node = call.args[0]
        model = literal(model_node, consts) if model_node is not None else None
        if model is None and isinstance(model_node, ast.Call):
            model = literal(kwarg(model_node, "model")) or literal(kwarg(model_node, "model_name")) or call_name(model_node)
        llm_cfg = literal(kwarg(call, "llm_config"))
        if model is None and isinstance(llm_cfg, dict):
            cl = llm_cfg.get("config_list")
            if isinstance(cl, list) and cl and isinstance(cl[0], dict):
                model = cl[0].get("model")
        instr_node = (kwarg(call, "instructions") or kwarg(call, "system_message") or kwarg(call, "backstory")
                      or kwarg(call, "prompt") or kwarg(call, "state_modifier") or kwarg(call, "system_prompt"))
        instr = literal(instr_node, consts) if instr_node is not None else None
        interpolated = []
        if isinstance(instr_node, ast.JoinedStr):
            for v in instr_node.values:
                if isinstance(v, ast.FormattedValue):
                    nm = call_name(v.value) if not isinstance(v.value, ast.Name) else v.value.id
                    interpolated.append(nm)
        elif isinstance(instr_node, ast.Call) and call_name(instr_node).endswith("format"):
            interpolated = [kw.arg or "?" for kw in instr_node.keywords] or ["format-args"]

        tools_node = kwarg(call, "tools")
        if tools_node is None and cn == "create_react_agent" and len(call.args) > 1:
            tools_node = call.args[1]
        tools: list[str] = []
        for e in getattr(tools_node, "elts", []) or []:
            if isinstance(e, ast.Name):
                tools.append(e.id)
            elif isinstance(e, ast.Call):
                inner = call_name(e)
                if inner.endswith(".as_tool") and isinstance(e.func, ast.Attribute) and isinstance(e.func.value, ast.Name):
                    tools.append("@agent:" + e.func.value.id)
                else:
                    tools.append(inner.split(".")[-1])
        handoffs = [e.id for e in getattr(kwarg(call, "handoffs"), "elts", []) or [] if isinstance(e, ast.Name)]

        max_it = None
        for k in ("max_iterations", "max_iter", "max_consecutive_auto_reply", "max_turns", "max_steps"):
            v = literal(kwarg(call, k), consts)
            if isinstance(v, int):
                max_it = v
                break
        oversight = None
        interrupt = literal(kwarg(call, "interrupt_before"))
        if interrupt:
            oversight = f"interrupt_before={interrupt}"
        him = literal(kwarg(call, "human_input_mode"))
        if isinstance(him, str):
            oversight = None if him.upper() == "NEVER" else f"human_input_mode={him}"
        code_exec = False
        sandboxed = None
        cec = kwarg(call, "code_execution_config")
        if cec is not None:
            cfg = literal(cec)
            if cfg is False:
                code_exec = False
            else:
                code_exec = True
                if isinstance(cfg, dict):
                    ud = cfg.get("use_docker")
                    sandboxed = ud if isinstance(ud, bool) else (True if isinstance(ud, str) else None)
                    if "executor" in cfg:
                        sandboxed = None
                ex = None
                if isinstance(cec, ast.Dict):
                    for k, v in zip(cec.keys, cec.values):
                        if literal(k) == "executor":
                            ex = call_name(v).split(".")[-1] if isinstance(v, ast.Call) else None
                if ex in CODE_EXEC_TOOLS:
                    sandboxed = CODE_EXEC_TOOLS[ex][1]
                ctx.inventory.code_execution.append(CodeExecutionSite(
                    "autogen_executor", rel, call.lineno, sandboxed, None, "code_execution_config"))
        if literal(kwarg(call, "allow_code_execution")) is True:
            code_exec = True
            mode = literal(kwarg(call, "code_execution_mode"))
            sandboxed = mode != "unsafe"
            ctx.inventory.code_execution.append(CodeExecutionSite(
                "crewai_code_execution", rel, call.lineno, sandboxed, None, f"code_execution_mode={mode or 'safe(default)'}"))
        if any(t in CODE_EXEC_TOOLS for t in tools):
            code_exec = True
            sandboxed = all(CODE_EXEC_TOOLS[t][1] is True for t in tools if t in CODE_EXEC_TOOLS)
        provider = None
        if isinstance(model, str):
            low = model.lower()
            provider = ("openai" if low.startswith(("gpt", "o1", "o3", "o4", "chatgpt")) else
                        "anthropic" if "claude" in low else "google" if "gemini" in low else
                        "mistral" if "mistral" in low else None)
        return Agent(
            name=str(name), framework=fw, file=rel, line=call.lineno, model=str(model) if model else None,
            provider=provider,
            instructions_excerpt=redact(str(instr)[:400]) if instr else None,
            instructions_mentions_approval=bool(instr and re.search(r"(?i)approv|confirm|ask the user|permission", str(instr))),
            instructions_include_untrusted_input=bool(interpolated and any(UNTRUSTED_VAR.search(x) for x in interpolated)),
            tools=tools, sub_agents=handoffs, max_iterations=max_it, max_iterations_source="code" if max_it else None,
            human_oversight=oversight, code_execution=code_exec, code_execution_sandboxed=sandboxed,
            allow_delegation=literal(kwarg(call, "allow_delegation")) if isinstance(literal(kwarg(call, "allow_delegation")), bool) else None,
            provenance="code",
        )

    def _analyse_function(self, fn: ast.AST, consts: dict[str, Any]) -> _FuncFacts:
        facts = _FuncFacts()
        local_consts = dict(consts)
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                v = literal(node.value, local_consts)
                if v is not None:
                    local_consts[node.targets[0].id] = v
        for node in ast.walk(fn):
            if not isinstance(node, ast.Call):
                continue
            cn = call_name(node)
            last = cn.split(".")[-1]
            dest = _http_call(node, local_consts)
            if dest:
                facts.destinations.append((dest[0], node.lineno, dest[1], dest[2]))
                facts.operations.add("network")
                if dest[2] or dest[1] in ("POST", "PUT", "PATCH"):
                    facts.operations.add("send")
                if dest[1] == "DELETE":
                    facts.operations.add("delete")
                if dest[1] in ("GET", None) and not dest[2]:
                    facts.data_access.add("web")
            if last in ("SMTP", "SMTP_SSL", "sendmail", "send_message") or cn.endswith("messages.send") or "send_email" in last:
                facts.operations.add("send")
                facts.data_access.add("email")
            if last in ("remove", "unlink", "rmtree", "rmdir") and ("os" in cn or "shutil" in cn or "Path" in cn or "path" in cn):
                facts.operations.add("delete")
                facts.data_access.add("files")
            if last in ("write_text", "write_bytes", "dump") or (last == "open" and _open_mode(node) in ("w", "a", "x")):
                facts.operations.add("write")
                facts.data_access.add("files")
            if last == "open" and _open_mode(node) in ("r", None):
                facts.operations.add("read")
                facts.data_access.add("files")
            ex = _exec_kind(node)
            if ex:
                facts.operations.add("execute")
                facts.exec_sites.append((ex, node.lineno))
            if last in ("execute", "executemany", "exec_driver_sql", "query", "run_query", "text") and node.args:
                sql = literal(node.args[0], local_consts)
                if isinstance(sql, str):
                    m = SQL_VERBS.match(sql)
                    if m:
                        verb = m.group(1).lower()
                        facts.data_access.add("database")
                        facts.operations.add({"select": "read", "insert": "write", "update": "write", "delete": "delete",
                                              "drop": "delete", "truncate": "delete", "alter": "admin", "grant": "admin",
                                              "create": "write"}[verb])
            scopes = kwarg(node, "scopes")
            if scopes is not None:
                val = literal(scopes, local_consts)
                for s in val if isinstance(val, list) else [val] if isinstance(val, str) else []:
                    if isinstance(s, str) and s not in facts.scopes:
                        facts.scopes.append(s)
                        info = scope_info(s)
                        if info:
                            facts.operations.update(o for o in info.operations if o == "read")
                if "drive" in str(val):
                    facts.data_access.add("documents")
                if "mail" in str(val):
                    facts.data_access.add("email")
            if last in ("getenv", "get") and ("environ" in cn or last == "getenv") and node.args:
                key = literal(node.args[0])
                if isinstance(key, str) and re.search(r"(?i)key|token|secret|credential|password|account", key):
                    facts.identity = facts.identity or f"env:{key}"
            if APPROVAL_CALL.search(last) and last not in ("confirmation",):
                facts.approval_call = True
        return facts

    def _add_dest(self, ctx: AuditContext, url: str, rel: str, line: int, method: str | None,
                  in_call: bool, carries: bool) -> None:
        if is_documentation_url(url):
            return
        host, cls = classify_host(url)
        for d in ctx.inventory.network:
            if d.url == url and d.file == rel and d.line == line:
                return
        ctx.inventory.network.append(NetworkDestination(url, host, rel, line, method, in_call, carries, cls))


# --- helpers ------------------------------------------------------------------------------

def _imports(tree: ast.Module) -> list[str]:
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out.extend(a.name for a in n.names)
        elif isinstance(n, ast.ImportFrom) and n.module:
            out.append(n.module)
    return out


def _calls(tree: ast.AST) -> list[ast.Call]:
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call)]


def _open_mode(call: ast.Call) -> str | None:
    mode = literal(kwarg(call, "mode")) if kwarg(call, "mode") is not None else (
        literal(call.args[1]) if len(call.args) > 1 else None)
    if isinstance(mode, str):
        for ch in ("w", "a", "x"):
            if ch in mode:
                return ch
        return "r"
    return None


def _http_call(call: ast.Call, consts: dict[str, Any]) -> tuple[str, str | None, bool] | None:
    cn = call_name(call)
    parts = cn.split(".")
    last = parts[-1]
    if last not in HTTP_METHODS:
        return None
    root = ".".join(parts[:-1]).lower()
    if not root or not any(r in root for r in HTTP_CLIENT_ROOTS):
        return None
    method = HTTP_METHODS[last]
    url_node = kwarg(call, "url") or (call.args[0] if call.args else None)
    if last == "request" and len(call.args) >= 2:
        method = str(literal(call.args[0]) or "").upper() or None
        url_node = call.args[1]
    url = literal(url_node, consts)
    if not isinstance(url, str):
        return None
    m = URL_RE.search(url)
    if not m:
        return None
    carries = any(kwarg(call, k) is not None for k in ("json", "data", "files", "content", "body"))
    if last == "urlopen" and len(call.args) > 1:
        carries = True
    return m.group(0), method, carries


def _exec_kind(call: ast.Call) -> str | None:
    cn = call_name(call)
    last = cn.split(".")[-1]
    if cn in ("exec", "eval", "builtins.exec", "builtins.eval"):
        if call.args and isinstance(call.args[0], ast.Constant):
            return None
        return "eval"
    if cn.startswith("subprocess.") or last in ("Popen", "check_output", "check_call") and "subprocess" in cn:
        return "subprocess"
    if cn in ("os.system", "os.popen", "os.execv", "os.execve", "os.spawnl", "os.startfile"):
        return "shell"
    if last in ("create_subprocess_shell", "create_subprocess_exec"):
        return "subprocess"
    return None
