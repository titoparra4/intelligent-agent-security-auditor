"""Reference identifiers used in findings.

Official names were checked against the published documents (see references/*.md for
links and version dates). Only identifiers with a verifiable correspondence are used; when
no reference applies, the list is left empty rather than inventing a mapping.
"""

ASI = {
    "ASI01": "ASI01:2026 Agent Goal Hijack",
    "ASI02": "ASI02:2026 Tool Misuse and Exploitation",
    "ASI03": "ASI03:2026 Identity and Privilege Abuse",
    "ASI04": "ASI04:2026 Agentic Supply Chain Vulnerabilities",
    "ASI05": "ASI05:2026 Unexpected Code Execution",
    "ASI06": "ASI06:2026 Memory & Context Poisoning",
    "ASI07": "ASI07:2026 Insecure Inter-Agent Communication",
    "ASI08": "ASI08:2026 Cascading Failures",
    "ASI09": "ASI09:2026 Human-Agent Trust Exploitation",
    "ASI10": "ASI10:2026 Rogue Agents",
}

LLM = {
    "LLM01": "LLM01:2026 Prompt Injection",
    "LLM02": "LLM02:2026 Sensitive Information Disclosure",
    "LLM03": "LLM03:2026 Excessive Agency",
    "LLM04": "LLM04:2026 Supply Chain",
    "LLM05": "LLM05:2026 Data and Model Poisoning",
    "LLM06": "LLM06:2026 Unbounded Consumption",
    "LLM07": "LLM07:2026 Misinformation",
    "LLM08": "LLM08:2026 Hidden Context Exposure",
    "LLM09": "LLM09:2026 Vector and Embedding Weaknesses",
    "LLM10": "LLM10:2026 Improper Output Handling",
}

NIST = {
    "GV-1.1": "NIST AI RMF GOVERN 1.1 (legal and regulatory requirements understood and managed)",
    "GV-6.1": "NIST AI RMF GOVERN 6.1 (policies for third-party entities and supply chain risk)",
    "MP-3.5": "NIST AI RMF MAP 3.5 (processes for human oversight defined)",
    "MP-4.1": "NIST AI RMF MAP 4.1 (approaches for mapping risks of components, incl. third-party)",
    "MS-2.7": "NIST AI RMF MEASURE 2.7 (security and resilience evaluated and documented)",
    "MS-2.10": "NIST AI RMF MEASURE 2.10 (privacy risk examined and documented)",
    "MG-2.4": "NIST AI RMF MANAGE 2.4 (mechanisms to supersede, disengage or deactivate)",
    "MG-4.1": "NIST AI RMF MANAGE 4.1 (post-deployment monitoring plans)",
    "600-IS": "NIST AI 600-1 Information Security",
    "600-DP": "NIST AI 600-1 Data Privacy",
    "600-VC": "NIST AI 600-1 Value Chain and Component Integration",
    "600-HAC": "NIST AI 600-1 Human-AI Configuration",
}

MCP = {
    "TOKEN_PASSTHROUGH": "MCP Security Best Practices: Token Passthrough",
    "CONFUSED_DEPUTY": "MCP Security Best Practices: Confused Deputy Problem",
    "SSRF": "MCP Security Best Practices: Server-Side Request Forgery",
    "AUTHZ": "MCP Specification: Authorization (HTTP transports)",
    "TOOL_SAFETY": "MCP Specification: Tools - Security Considerations",
    "LOCAL_SERVER": "MCP Security Best Practices: Local MCP Server Compromise",
}

ATLAS = {
    "PI_DIRECT": "MITRE ATLAS AML.T0051.000 LLM Prompt Injection: Direct",
    "PI_INDIRECT": "MITRE ATLAS AML.T0051.001 LLM Prompt Injection: Indirect",
    "JAILBREAK": "MITRE ATLAS AML.T0054 LLM Jailbreak",
    "DATA_LEAK": "MITRE ATLAS AML.T0057 LLM Data Leakage",
    "PLUGIN": "MITRE ATLAS AML.T0053 LLM Plugin Compromise",
    "SUPPLY": "MITRE ATLAS AML.T0010 ML Supply Chain Compromise",
    "RAG_POISON": "MITRE ATLAS AML.T0070 RAG Poisoning",
}


def asi(*keys: str) -> list[str]:
    return [ASI[k] for k in keys]


def llm(*keys: str) -> list[str]:
    return [LLM[k] for k in keys]


def nist(*keys: str) -> list[str]:
    return [NIST[k] for k in keys]
