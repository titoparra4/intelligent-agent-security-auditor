"""Command-line interface: ``agent-security-auditor``.

Exit codes (stable, documented in docs/usage.md):

====  ==========================================================================
0     READY (or success for informational commands)
10    READY_WITH_RISKS (0 with ``--allow-risks``)
20    NOT_READY, or ``compare``/``--mode ci`` detected a regression
30    INSUFFICIENT_EVIDENCE
64    usage error (bad arguments)
65    invalid input data (e.g. malformed assessment JSON, unreadable target)
70    scanner error - the audit is incomplete and MUST NOT be treated as passed
75    dynamic-test preconditions not met (no authorization/scope/isolation) - nothing executed
78    invalid policy
====  ==========================================================================
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from agent_security_auditor import DISCLAIMER, SCHEMA_VERSION, __version__

EXIT = {"READY": 0, "READY_WITH_RISKS": 10, "NOT_READY": 20, "INSUFFICIENT_EVIDENCE": 30}
EX_USAGE, EX_DATAERR, EX_SOFTWARE, EX_SANDBOX, EX_CONFIG = 64, 65, 70, 75, 78


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # argparse would exit 2, which collides with nothing we use, but be explicit
        self.print_usage(sys.stderr)
        self.exit(EX_USAGE, f"{self.prog}: error: {message}\n")


def _common_target(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", help="path to the agent project (directory or single file)")
    p.add_argument("--policy", default=None, help="builtin profile (basic-agent, enterprise-agent, mcp-integrated-agent, "
                                                  "high-risk-autonomous-agent) or policy file (default: basic-agent)")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="exclude paths (repeatable)")
    p.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024, help="skip files larger than this")


def build_parser() -> argparse.ArgumentParser:
    p = _Parser(prog="agent-security-auditor",
                description="Evidence-based security auditor for AI agents (offline, static by default).",
                epilog=DISCLAIMER)
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)

    a = sub.add_parser("audit", help="run a full audit and produce reports",
                       description="Run a full audit. Default: STATIC mode, read-only, offline.")
    _common_target(a)
    a.add_argument("--mode", choices=["static", "threat-model", "dynamic", "ci"], default="static")
    a.add_argument("--format", default="markdown,json", help="comma list: json,markdown,sarif,html (default markdown,json)")
    a.add_argument("--output", "-o", default=None, help="directory for report files (default: print summary only)")
    a.add_argument("--basename", default="agent-security-assessment", help="report file base name")
    a.add_argument("--baseline", default=None, help="previous assessment JSON (CI mode / stable first_seen)")
    a.add_argument("--fail-on-new", default="high", choices=["any", "info", "low", "medium", "high", "critical", "never"],
                   help="CI mode: severity of newly introduced findings that fails the gate (default high)")
    a.add_argument("--allow-risks", action="store_true", help="exit 0 instead of 10 for READY_WITH_RISKS")
    a.add_argument("--vuln-db", default=None, help="offline OSV advisory directory (opt-in; no network)")
    a.add_argument("--assessment-id", default=None, help="fixed assessment id (reproducible output)")
    a.add_argument("--target-name", default=None, help="display name of the target")
    a.add_argument("--plugins", action="store_true", help="load analyzers registered via entry points")
    a.add_argument("--harness", default=None, help="dynamic mode: harness file inside the target")
    a.add_argument("--scope", default=None, help="dynamic mode: scope/authorization YAML")
    a.add_argument("--authorize", action="store_true", help="dynamic mode: explicit consent to run tests in the sandbox")
    a.add_argument("--quiet", "-q", action="store_true", help="no console summary")

    for name, helptext in (("architecture", "inventory, trust boundaries and data-flow diagram"),
                           ("permissions", "tool permission matrix"), ("mcp", "MCP servers, tools and MCP findings"),
                           ("data-flow", "source -> sink data flows and egress inventory"),
                           ("threat-model", "threat model (THREAT MODEL mode, no controls evaluated)")):
        sp = sub.add_parser(name, help=helptext, description=helptext)
        _common_target(sp)
        sp.add_argument("--format", choices=["text", "json", "markdown"], default="text")

    t = sub.add_parser("test", help="adversarial test plan, or controlled dynamic tests in an isolated sandbox",
                       description="Without --harness: print the applicable synthetic test plan (nothing is executed). "
                                   "With --harness/--scope/--authorize: verify isolation, then run scenarios in the sandbox.")
    _common_target(t)
    t.add_argument("--list", action="store_true", help="list all scenarios")
    t.add_argument("--harness", default=None)
    t.add_argument("--scope", default=None)
    t.add_argument("--authorize", action="store_true")
    t.add_argument("--only", action="append", default=None, metavar="TEST_ID")
    t.add_argument("--format", choices=["text", "json"], default="text")

    c = sub.add_parser("compare", help="compare two assessment JSON files (CI gate)")
    c.add_argument("previous")
    c.add_argument("current")
    c.add_argument("--fail-on", default="high", choices=["any", "info", "low", "medium", "high", "critical", "never"])
    c.add_argument("--format", choices=["text", "json"], default="text")

    r = sub.add_parser("report", help="re-render an assessment JSON into other formats")
    r.add_argument("assessment")
    r.add_argument("--format", default="markdown,html,sarif")
    r.add_argument("--output", "-o", required=True)
    r.add_argument("--basename", default="agent-security-assessment")

    pol = sub.add_parser("policy", help="validate or inspect security policies")
    psub = pol.add_subparsers(dest="policy_command", required=True, parser_class=_Parser)
    pv = psub.add_parser("validate", help="validate a policy file against the schema")
    pv.add_argument("file")
    ps = psub.add_parser("show", help="show the effective policy")
    ps.add_argument("ref")
    psub.add_parser("list", help="list builtin profiles")

    sub.add_parser("version", help="print version information")
    return p


# --------------------------------------------------------------------------------------------

def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        handler = {
            "audit": cmd_audit, "architecture": cmd_view, "permissions": cmd_view, "mcp": cmd_view,
            "data-flow": cmd_view, "threat-model": cmd_view, "test": cmd_test, "compare": cmd_compare,
            "report": cmd_report, "policy": cmd_policy, "version": cmd_version,
        }[args.command]
        return handler(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EX_SOFTWARE


def _load_policy(ref: str | None):
    from agent_security_auditor.policies import PolicyError, load_policy

    try:
        return load_policy(ref), None
    except PolicyError as exc:
        msg = f"invalid policy: {exc}" + "".join(f"\n  - {e}" for e in exc.errors)
        return None, msg


def _limits(args: argparse.Namespace):
    from agent_security_auditor.core.discovery import DiscoveryLimits

    return DiscoveryLimits(max_file_bytes=args.max_file_bytes)


def _run(args: argparse.Namespace, mode, options: dict[str, Any] | None = None, baseline=None):
    from agent_security_auditor.core.discovery import DiscoveryError
    from agent_security_auditor.core.engine import run_audit

    policy, err = _load_policy(args.policy)
    if err:
        print(err, file=sys.stderr)
        return None, EX_CONFIG
    try:
        a = run_audit(args.target, mode, policy, exclude=args.exclude, limits=_limits(args), options=options or {},
                      assessment_id=getattr(args, "assessment_id", None), baseline=baseline,
                      plugins=getattr(args, "plugins", False))
    except DiscoveryError as exc:
        print(f"cannot audit target: {exc}", file=sys.stderr)
        return None, EX_DATAERR
    return a, 0


def _load_assessment(path: str):
    from agent_security_auditor.core.schema import load_schema, validate
    from agent_security_auditor.models.assessment import Assessment

    p = Path(path)
    if not p.is_file() or p.stat().st_size > 64 * 1024 * 1024:
        raise ValueError(f"assessment not found or too large: {path}")
    data = json.loads(p.read_text("utf-8"))
    errs = validate(data, load_schema("assessment"))
    if errs:
        raise ValueError("assessment JSON does not match schema: " + "; ".join(errs[:5]))
    return Assessment.from_dict(data)


def cmd_audit(args: argparse.Namespace) -> int:
    from agent_security_auditor.core.compare import compare, has_regression, public
    from agent_security_auditor.models.assessment import Mode
    from agent_security_auditor.reporters import console_summary, write_reports

    mode = Mode(args.mode)
    options: dict[str, Any] = {"vuln_db": args.vuln_db, "target_name": args.target_name}
    if args.vuln_db and not Path(args.vuln_db).is_dir():
        print(f"--vuln-db directory not found: {args.vuln_db}", file=sys.stderr)
        return EX_USAGE
    if mode == Mode.DYNAMIC:
        from agent_security_auditor.sandbox.runner import SandboxRefused, run_dynamic

        if not (args.harness and args.scope):
            print("dynamic mode requires --harness, --scope and --authorize", file=sys.stderr)
            return EX_SANDBOX
        try:
            results, report, _scope = run_dynamic(args.target, args.harness, args.scope, args.authorize)
        except SandboxRefused as exc:
            print(f"dynamic testing refused: {exc}", file=sys.stderr)
            if exc.details:
                print(json.dumps(exc.details, indent=2), file=sys.stderr)
            return EX_SANDBOX
        options.update({"dynamic_results": results, "isolation_report": report.to_dict()})
    baseline = None
    if args.baseline:
        try:
            baseline = _load_assessment(args.baseline)
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"invalid baseline: {exc}", file=sys.stderr)
            return EX_DATAERR
    elif mode == Mode.CI:
        print("ci mode requires --baseline", file=sys.stderr)
        return EX_USAGE
    a, code = _run(args, mode, options, baseline)
    if a is None:
        return code
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    if args.output:
        from agent_security_auditor.reporters import FORMATS
        bad = [f for f in formats if f not in FORMATS and f != "md"]
        if bad:
            print(f"unknown format(s): {', '.join(bad)}", file=sys.stderr)
            return EX_USAGE
        written = write_reports(a, args.output, formats, args.basename)
    else:
        written = []
    if not args.quiet:
        print(console_summary(a))
        for w in written:
            print(f"wrote {w}")
    if a.errors:
        return EX_SOFTWARE
    verdict_code = EXIT[a.readiness.verdict.value]
    if args.allow_risks and verdict_code == 10:
        verdict_code = 0
    if baseline is not None and mode == Mode.CI:
        diff = compare(baseline, a)
        if args.output:
            Path(args.output, f"{args.basename}.diff.json").write_text(json.dumps(public(diff), indent=2), "utf-8")
        if not args.quiet:
            print(_diff_text(diff))
        if has_regression(diff, args.fail_on_new):
            return 20
    return verdict_code


def cmd_view(args: argparse.Namespace) -> int:
    from agent_security_auditor.models.assessment import Mode

    mode = Mode.THREAT_MODEL if args.command == "threat-model" else Mode.STATIC
    a, code = _run(args, mode)
    if a is None:
        return code
    inv = a.inventory
    if args.command == "architecture":
        data = {"agents": inv["agents"], "tools": [t["name"] for t in inv["tools"]], "mcp_servers": [m["name"] for m in inv["mcp_servers"]],
                "memory": inv["memory"], "frameworks": inv["frameworks"], "trust_boundaries": a.threat_model.get("trust_boundaries"),
                "delegation_graph": a.delegation_graph, "dataflow_mermaid": a.threat_model.get("dataflow_mermaid")}
        text = _arch_text(a)
    elif args.command == "permissions":
        data = a.permission_matrix
        text = _table_text(["Tool", "Identity", "Permissions", "Data Access", "Operations", "Risk", "Required Approval"],
                           [[r["tool"], r["identity"], ", ".join(r["permissions"]), ", ".join(r["data_access"]),
                             ", ".join(r["operations"]), r["risk"], r["required_approval"]] for r in data])
        text += "\nprovenance: " + ", ".join(f"{r['tool']}={r['permission_provenance']}" for r in data)
    elif args.command == "mcp":
        data = {"servers": inv["mcp_servers"], "findings": [f.to_dict() for f in a.findings if f.module == "M06"],
                "controls": [c.to_dict() for c in a.controls if c.module == "M06"]}
        text = _table_text(["Server", "Transport", "Pinned", "Auth", "Tools", "Location"],
                           [[m["name"], m["transport"], m["version_pinned"], m["auth"], len(m["tools"]), f"{m['file']}:{m['line']}"]
                            for m in inv["mcp_servers"]]) + "\n" + "\n".join(
            f"{f.display_id} {f.severity.value} {f.status.value} {f.rule_id} {f.title} — {f.asset}" for f in a.findings if f.module == "M06") \
            + "\n" + "\n".join(f"{c.control_id} {c.status.value}: {c.rationale}" for c in a.controls if c.module == "M06")
    elif args.command == "data-flow":
        data = {"flows": a.data_flows, "egress": a.threat_model.get("egress_inventory")}
        text = _table_text(["Source", "Sensitivity", "Sink", "Destination", "Controls", "Risk"],
                           [[f["source"], ", ".join(f["sensitivity"]), f["sink"], f["destination"], ", ".join(f["controls"]) or "NONE", f["risk"]]
                            for f in a.data_flows]) + "\n\nEgress:\n" + _table_text(
            ["Host", "Class", "Method", "Payload", "Allowlisted"],
            [[e["host"], e["class"], e["method"], e["payload"], e["allowlisted"]] for e in a.threat_model.get("egress_inventory", [])])
    else:
        data = a.threat_model
        tm = a.threat_model
        text = ("Trust boundaries:\n" + "\n".join(f"  {t['id']} {t['name']}: {t['crosses']}" for t in tm.get("trust_boundaries", []))
                + "\n\nThreats:\n" + "\n".join(f"  {t['id']} {t['title']} [{t['owasp']}] surface={t['surface']}" for t in tm.get("threats", []))
                + "\n\nAssets:\n" + "\n".join(f"  {x['asset']} ({x['type']}) {', '.join(x['sensitivity'])}" for x in tm.get("assets", []))
                + "\n\n" + (tm.get("dataflow_mermaid") or ""))
    if args.format == "json":
        print(json.dumps(data, indent=2, default=str))
    elif args.format == "markdown":
        print("```\n" + text + "\n```")
    else:
        print(text)
    return EX_SOFTWARE if a.errors else 0


def cmd_test(args: argparse.Namespace) -> int:
    from agent_security_auditor.models.assessment import Mode
    from agent_security_auditor.sandbox.scenarios import catalog

    if args.list:
        for s in catalog():
            print(f"{s.test_id:<13} {s.category:<30} {s.objective}")
        return 0
    if not args.harness:
        a, code = _run(args, Mode.STATIC)
        if a is None:
            return code
        rows = a.test_plan
        if args.format == "json":
            print(json.dumps(rows, indent=2))
        else:
            print(_table_text(["Test ID", "Objective", "Preconditions", "Expected Behavior", "Result"],
                              [[r["test_id"], r["objective"], r["preconditions"], r["expected_behavior"],
                                r["result"] if r["applicable"] else "NOT_APPLICABLE"] for r in rows]))
            print("\nNothing was executed. Dynamic execution requires --harness, --scope and --authorize in an isolated sandbox.")
        return 0
    from agent_security_auditor.sandbox.runner import SandboxRefused, run_dynamic

    if not args.scope:
        print("dynamic tests require --scope", file=sys.stderr)
        return EX_SANDBOX
    try:
        results, report, scope = run_dynamic(args.target, args.harness, args.scope, args.authorize, only=args.only)
    except SandboxRefused as exc:
        print(f"dynamic testing refused: {exc}", file=sys.stderr)
        if exc.details:
            print(json.dumps(exc.details, indent=2), file=sys.stderr)
        return EX_SANDBOX
    if args.format == "json":
        print(json.dumps({"isolation": report.to_dict(), "authorized_by": scope.authorized_by, "results": results}, indent=2))
    else:
        print(f"Isolation verified ({len(report.checks)} checks). Authorized by: {scope.authorized_by}")
        print(_table_text(["Test ID", "Result", "Observed"], [[r["test_id"], r["result"], r.get("observed", "")] for r in results]))
    failed = [r for r in results if r["result"] in ("FAIL", "ERROR")]
    return 20 if failed else 0


def cmd_compare(args: argparse.Namespace) -> int:
    from agent_security_auditor.core.compare import compare, has_regression, public

    try:
        prev, curr = _load_assessment(args.previous), _load_assessment(args.current)
    except (ValueError, json.JSONDecodeError, KeyError) as exc:
        print(f"invalid assessment: {exc}", file=sys.stderr)
        return EX_DATAERR
    diff = compare(prev, curr)
    if args.format == "json":
        print(json.dumps(public(diff), indent=2))
    else:
        print(_diff_text(diff))
    return 20 if has_regression(diff, args.fail_on) else 0


def cmd_report(args: argparse.Namespace) -> int:
    from agent_security_auditor.reporters import FORMATS, write_reports

    try:
        a = _load_assessment(args.assessment)
    except (ValueError, json.JSONDecodeError, KeyError) as exc:
        print(f"invalid assessment: {exc}", file=sys.stderr)
        return EX_DATAERR
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    bad = [f for f in formats if f not in FORMATS and f != "md"]
    if bad:
        print(f"unknown format(s): {', '.join(bad)}", file=sys.stderr)
        return EX_USAGE
    for w in write_reports(a, args.output, formats, args.basename):
        print(f"wrote {w}")
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    from agent_security_auditor.policies import BUILTIN_PROFILES, validate_policy_file

    if args.policy_command == "list":
        for name in BUILTIN_PROFILES:
            print(name)
        return 0
    if args.policy_command == "validate":
        errs = validate_policy_file(args.file)
        if errs:
            print("INVALID", file=sys.stderr)
            for e in errs:
                print(f"  - {e}", file=sys.stderr)
            return EX_CONFIG
        print(f"VALID: {args.file}")
        return 0
    policy, err = _load_policy(args.ref)
    if err:
        print(err, file=sys.stderr)
        return EX_CONFIG
    print(json.dumps(policy.describe() | {
        "allowed_network_destinations": policy.allowed_network_destinations, "forbidden_tools": policy.forbidden_tools,
        "authorized_tools": policy.authorized_tools, "forbidden_operations": policy.forbidden_operations,
        "approval_required_for": policy.approval_required_for, "denied_scopes": policy.denied_scopes}, indent=2))
    return 0


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"intelligent-agent-security-auditor {__version__} (finding/assessment schema {SCHEMA_VERSION}, Python {sys.version.split()[0]})")
    return 0


# --- text helpers ----------------------------------------------------------------------------

def _table_text(headers: list[str], rows: list[list[Any]]) -> str:
    cells = [[str(h) for h in headers]] + [[("" if c is None else str(c)) for c in r] for r in rows]
    widths = [min(48, max(len(r[i]) for r in cells)) for i in range(len(headers))]
    out = []
    for n, r in enumerate(cells):
        out.append("  ".join(c[:w].ljust(w) for c, w in zip(r, widths)).rstrip())
        if n == 0:
            out.append("  ".join("-" * w for w in widths))
    if not rows:
        out.append("(none)")
    return "\n".join(out)


def _arch_text(a) -> str:
    inv = a.inventory
    lines = [f"Frameworks: {', '.join(inv['frameworks']) or 'none'}   Manifest: {inv['manifest_file'] or 'none'}", "Agents:"]
    for ag in inv["agents"]:
        lines.append(f"  - {ag['name']} [{ag['framework']}] model={ag.get('model') or 'UNKNOWN'} tools={', '.join(ag['tools']) or '-'} "
                     f"sub_agents={', '.join(ag['sub_agents']) or '-'} max_iterations={ag.get('max_iterations')}")
    lines.append("Tools:")
    for t in inv["tools"]:
        lines.append(f"  - {t['name']} ops={','.join(t['operations']) or '?'} data={','.join(t['data_access']) or '-'} source={t['source']}")
    lines.append("MCP servers:")
    for m in inv["mcp_servers"]:
        lines.append(f"  - {m['name']} ({m['transport']}) tools={len(m['tools'])}")
    lines.append("Memory:")
    for m in inv["memory"]:
        lines.append(f"  - {m['name']} kind={m['kind']} scope={m['scope']}")
    lines.append("Trust boundaries:")
    for tb in a.threat_model.get("trust_boundaries", []):
        lines.append(f"  - {tb['id']} {tb['name']}: {tb['crosses']}")
    lines += ["", a.threat_model.get("dataflow_mermaid", "")]
    return "\n".join(lines)


def _diff_text(diff: dict[str, Any]) -> str:
    d = diff
    lines = [f"Baseline {d['baseline']} -> current {d['current']}",
             f"Readiness: {d['readiness']['before']} -> {d['readiness']['after']}   Score: {d['score']['before']} -> {d['score']['after']}"]
    for key in ("new_tools", "removed_tools", "new_mcp_servers", "new_network_destinations", "new_dependencies", "new_agents"):
        if d[key]:
            lines.append(f"{key.replace('_', ' ')}: {', '.join(d[key])}")
    for p in d["new_permissions"]:
        lines.append(f"new permission on {p['tool']}: {p.get('added') or p.get('added_operations')}")
    for p in d["new_data_access"]:
        lines.append(f"new data access on {p['tool']}: {', '.join(p['added'])}")
    for f in d["introduced_findings"]:
        lines.append(f"+ {f['severity']} {f['rule_id']} {f['title']} — {f['asset']}")
    for f in d["resolved_findings"]:
        lines.append(f"- resolved {f['rule_id']} {f['title']} — {f['asset']}")
    for c in d["controls_no_longer_verified"]:
        lines.append(f"! control {c['control_id']}: {c['before']} -> {c['after']}")
    if len(lines) == 2:
        lines.append("no changes in permissions, tools, MCP servers, destinations, dependencies or findings")
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
