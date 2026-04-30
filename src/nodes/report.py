"""Report node — aggregates all findings into a final penetration test report."""

from langchain_core.messages import HumanMessage

from src.nodes.base import BaseNode
from src.state import SwarmGraphState


class ReportNode(BaseNode):
    """Aggregate all findings into a final report message."""

    async def execute(self, state: SwarmGraphState) -> dict:
        findings = state.get("findings", [])
        results = state.get("agent_results", [])

        completed = [r for r in results if r.completed]
        failed = [r for r in results if r.error]

        # Sort findings by severity
        severity_order = {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
        }
        sorted_findings = sorted(
            findings,
            key=lambda f: severity_order.get(f.severity.value, 5),
        )

        custom_used = sum(1 for r in results if r.methodology == "custom")

        summary_lines = [
            "## SwarmAttacker Penetration Test Report",
            f"**Target:** {state.get('target_url', 'unknown')}",
            f"**Scope:** {state.get('target_scope', 'unknown')}",
            f"**Agents completed:** {len(completed)}",
            f"**Agents failed:** {len(failed)}",
            f"**Total findings:** {len(findings)}",
            f"**WAF detected:** {'Yes' if state.get('waf_detected') else 'No'}",
            f"**Stealth level:** {state.get('stealth_level', 0)}",
            f"**Custom configs used:** {custom_used}",
            "",
        ]

        if sorted_findings:
            summary_lines.append("### Findings (by severity)")
            for f in sorted_findings:
                lines = [f"#### [{f.severity.value.upper()}] {f.title}"]
                lines.append(f"- **Category:** {f.category}")
                if f.url:
                    lines.append(f"- **URL:** {f.url}")
                if f.cwe:
                    lines.append(f"- **CWE:** {f.cwe}")
                lines.append(f"- **Found by:** {f.agent_id}")
                if f.evidence:
                    lines.append(f"- **Evidence:** {f.evidence[:200]}")
                summary_lines.extend(lines)
                summary_lines.append("")
        else:
            summary_lines.append("### No vulnerabilities found")
            summary_lines.append(
                "The swarm completed testing but did not identify any "
                "vulnerabilities. This could mean the target is well-secured "
                "or that additional testing methodologies are needed."
            )

        if failed:
            summary_lines.append("\n### Agent Errors")
            for r in failed:
                summary_lines.append(f"- **{r.agent_id}:** {r.error}")

        # Agent summary
        summary_lines.append("\n### Agent Summary")
        for r in results:
            status = "completed" if r.completed else f"FAILED: {r.error}"
            finding_count = len(r.findings) if r.findings else 0
            summary_lines.append(
                f"- **{r.agent_id}** ({r.methodology}/{r.config_name}): "
                f"{status}, {finding_count} findings"
            )

        return {
            "messages": [HumanMessage(content="\n".join(summary_lines))],
        }


report_node = ReportNode()
