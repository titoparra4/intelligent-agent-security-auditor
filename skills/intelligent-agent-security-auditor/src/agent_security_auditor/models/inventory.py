"""Normalized component inventory reconstructed from the audited project.

Every adapter (manifest, MCP config, Python frameworks, dependency files ...) writes into
this one model so analyzers never need to know which framework produced a component.

``provenance`` records *how* a fact is known:

* ``declared``  - stated in a manifest / config by the agent owner (not proof of enforcement)
* ``configured``- present in machine-consumed configuration (e.g. OAuth scopes requested)
* ``code``      - derived from static analysis of the source code
* ``inferred``  - guessed from names / descriptions; weakest evidence
* ``verified``  - observed during a controlled dynamic test
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

OPERATIONS = ("read", "write", "delete", "send", "execute", "financial", "infra", "network", "admin")
DESTRUCTIVE_OPERATIONS = frozenset({"write", "delete", "send", "execute", "financial", "infra", "admin"})
IRREVERSIBLE_OPERATIONS = frozenset({"delete", "send", "financial", "infra"})
UNTRUSTED_CONTENT_KINDS = frozenset({"email", "web", "documents", "rag", "tickets", "chat", "files"})
SENSITIVE_DATA = frozenset({"pii", "financial", "credentials", "health", "confidential"})


@dataclass
class Tool:
    name: str
    source: str  # manifest | code:<framework> | mcp:<server>
    file: str | None = None
    line: int | None = None
    description: str = ""
    agents: list[str] = field(default_factory=list)
    operations: list[str] = field(default_factory=list)
    data_access: list[str] = field(default_factory=list)
    sensitivity: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    permission_provenance: str = "inferred"
    identity: str | None = None
    requires_approval: bool | None = None
    approval_provenance: str | None = None  # declared | code
    approval_enforced_by: str | None = None
    returns_untrusted_content: bool | None = None
    output_handling: str | None = None  # e.g. "isolated", "delimited", "quarantined"
    network_destinations: list[str] = field(default_factory=list)
    mcp_server: str | None = None
    production_target: bool = False
    tenant_scoped: bool | None = None

    @property
    def is_destructive(self) -> bool:
        return bool(set(self.operations) & DESTRUCTIVE_OPERATIONS)

    @property
    def is_irreversible(self) -> bool:
        return bool(set(self.operations) & IRREVERSIBLE_OPERATIONS)

    @property
    def is_egress(self) -> bool:
        return "send" in self.operations or "network" in self.operations

    @property
    def reads_untrusted(self) -> bool:
        if self.returns_untrusted_content is not None:
            return self.returns_untrusted_content
        return bool(set(self.data_access) & UNTRUSTED_CONTENT_KINDS) and "read" in self.operations

    @property
    def touches_sensitive(self) -> bool:
        return bool(set(self.sensitivity) & SENSITIVE_DATA)


@dataclass
class Agent:
    name: str
    framework: str
    file: str | None = None
    line: int | None = None
    model: str | None = None
    provider: str | None = None
    instructions_excerpt: str | None = None  # redacted, truncated
    instructions_mentions_approval: bool = False
    instructions_include_untrusted_input: bool = False
    tools: list[str] = field(default_factory=list)
    sub_agents: list[str] = field(default_factory=list)
    max_iterations: int | None = None
    max_iterations_source: str | None = None
    budget_limit: str | None = None
    kill_switch: str | None = None
    human_oversight: str | None = None
    code_execution: bool = False
    code_execution_sandboxed: bool | None = None
    allow_delegation: bool | None = None
    exposed_to_untrusted_input: bool | None = None
    identity: str | None = None
    provenance: str = "code"


@dataclass
class McpTool:
    name: str
    description: str = ""
    file: str | None = None
    line: int | None = None


@dataclass
class McpServer:
    name: str
    transport: str  # stdio | http | sse | unknown
    file: str | None = None
    line: int | None = None
    command: str | None = None
    args: list[str] = field(default_factory=list)
    url: str | None = None
    package: str | None = None
    version_pinned: bool | None = None
    env_keys: list[str] = field(default_factory=list)
    inline_secret_keys: list[str] = field(default_factory=list)
    header_keys: list[str] = field(default_factory=list)
    auth: str = "unknown"  # oauth | bearer | api_key | none | unknown | not_applicable
    tools: list[McpTool] = field(default_factory=list)
    tool_hashes: dict[str, str] = field(default_factory=dict)  # pinned definitions (optional lock)
    trusted: bool | None = None


@dataclass
class MemoryStore:
    name: str
    kind: str  # short_term | long_term | vector | cache
    file: str | None = None
    line: int | None = None
    scope: str = "unknown"  # per_user | per_tenant | per_session | shared | unknown
    ttl: str | None = None
    provenance_tracking: bool | None = None
    write_sources: list[str] = field(default_factory=list)
    injected_into: str | None = None  # context | system_prompt
    deletion_supported: bool | None = None
    provenance: str = "declared"


@dataclass
class DataSource:
    name: str
    kind: str
    sensitivity: list[str] = field(default_factory=list)
    file: str | None = None
    line: int | None = None


@dataclass
class NetworkDestination:
    url: str
    host: str
    file: str | None = None
    line: int | None = None
    method: str | None = None
    in_http_call: bool = False
    carries_data: bool = False
    classification: str = "external"  # loopback | private | reserved | external | exfil_service
    declared: bool = False


@dataclass
class Dependency:
    name: str
    ecosystem: str
    version_spec: str | None = None
    pinned: bool = False
    source: str = "registry"  # registry | vcs | url | path
    file: str | None = None
    line: int | None = None


@dataclass
class Delegation:
    from_agent: str
    to_agent: str
    inherit_permissions: bool | None = None
    authenticated: bool | None = None
    channel: str | None = None
    file: str | None = None
    line: int | None = None
    provenance: str = "code"


@dataclass
class CodeExecutionSite:
    kind: str  # python_repl | shell | eval | subprocess | docker | autogen_executor
    file: str
    line: int | None = None
    sandboxed: bool | None = None
    within_tool: str | None = None
    note: str = ""


@dataclass
class Inventory:
    agents: list[Agent] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    mcp_servers: list[McpServer] = field(default_factory=list)
    memory: list[MemoryStore] = field(default_factory=list)
    data_sources: list[DataSource] = field(default_factory=list)
    network: list[NetworkDestination] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    delegations: list[Delegation] = field(default_factory=list)
    code_execution: list[CodeExecutionSite] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    manifest_file: str | None = None
    adapters_used: list[str] = field(default_factory=list)
    declared_allowed_destinations: list[str] = field(default_factory=list)
    lockfiles: list[str] = field(default_factory=list)
    multi_user: bool | None = None
    telemetry_declared: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    # -- lookup helpers -------------------------------------------------------------------
    def tool(self, name: str) -> Tool | None:
        for t in self.tools:
            if t.name == name:
                return t
        return None

    def agent(self, name: str) -> Agent | None:
        for a in self.agents:
            if a.name == name:
                return a
        return None

    def add_tool(self, tool: Tool) -> Tool:
        """Merge by name: manifest declarations enrich code-detected tools and vice versa."""
        existing = self.tool(tool.name)
        if existing is None:
            self.tools.append(tool)
            return tool
        _merge_tool(existing, tool)
        return existing

    def add_agent(self, agent: Agent) -> Agent:
        existing = self.agent(agent.name)
        if existing is None:
            self.agents.append(agent)
            return agent
        for f in ("model", "provider", "instructions_excerpt", "max_iterations", "max_iterations_source",
                  "budget_limit", "kill_switch", "human_oversight", "code_execution_sandboxed",
                  "allow_delegation", "exposed_to_untrusted_input", "identity"):
            if getattr(existing, f) is None and getattr(agent, f) is not None:
                setattr(existing, f, getattr(agent, f))
        existing.code_execution = existing.code_execution or agent.code_execution
        existing.instructions_mentions_approval |= agent.instructions_mentions_approval
        existing.instructions_include_untrusted_input |= agent.instructions_include_untrusted_input
        for t in agent.tools:
            if t not in existing.tools:
                existing.tools.append(t)
        for s in agent.sub_agents:
            if s not in existing.sub_agents:
                existing.sub_agents.append(s)
        if existing.file is None:
            existing.file, existing.line = agent.file, agent.line
        return existing

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def _merge_tool(dst: Tool, src: Tool) -> None:
    rank = {"inferred": 0, "declared": 1, "configured": 2, "code": 2, "verified": 3}
    for f in ("operations", "data_access", "sensitivity", "permissions", "network_destinations", "agents"):
        merged = list(getattr(dst, f))
        for v in getattr(src, f):
            if v not in merged:
                merged.append(v)
        setattr(dst, f, merged)
    if rank.get(src.permission_provenance, 0) > rank.get(dst.permission_provenance, 0):
        dst.permission_provenance = src.permission_provenance
    for f in ("identity", "approval_enforced_by", "output_handling", "mcp_server", "returns_untrusted_content",
              "tenant_scoped"):
        if getattr(dst, f) is None and getattr(src, f) is not None:
            setattr(dst, f, getattr(src, f))
    if src.requires_approval is not None:
        # code evidence beats a declaration
        if dst.requires_approval is None or src.approval_provenance == "code":
            dst.requires_approval = src.requires_approval
            dst.approval_provenance = src.approval_provenance
    if not dst.description and src.description:
        dst.description = src.description
    if dst.file is None:
        dst.file, dst.line = src.file, src.line
    if src.source not in dst.source.split("+"):
        dst.source = dst.source + "+" + src.source
    dst.production_target = dst.production_target or src.production_target
