"""Report node — synthesize canonical findings into Markdown and PDF artifacts."""

from __future__ import annotations

import logging
from pathlib import Path

from langchain_core.messages import HumanMessage

from src.nodes.base import BaseNode
from src.reporting.content import (
    build_report_content,
    parse_synthesis,
    synthesis_input,
)
from src.reporting.markdown_report import render_markdown
from src.state import SwarmGraphState

logger = logging.getLogger(__name__)

REPORTING_SKILL_NAME = "reporting"


_SYNTHESIS_REQUEST = """
Create the report prose enrichment for the supplied canonical findings.

Return exactly this JSON shape:
{
  "executive": {
    "risk_rationale": "one short paragraph",
    "attacker_outcomes": ["up to four concise capabilities"],
    "assets_at_risk": ["up to six concrete assets or data types"],
    "priority_actions": ["up to five ordered defensive actions"],
    "limitations": "one short evidence or coverage limitation"
  },
  "findings": [
    {
      "source_index": 1,
      "business_impact": "one or two plain-language sentences",
      "assets_at_risk": ["concrete affected assets or data"],
      "root_cause": "the underlying control failure",
      "attack_narrative": ["two to five ordered, evidence-grounded steps"],
      "remediation": ["two to four specific defensive actions"],
      "validation_guidance": "the secure result a retest should observe"
    }
  ]
}

Return one finding object for every source_index. Return JSON only.

Canonical engagement data follows:
""".strip()


class ReportNode(BaseNode):
    """Create a client-facing report from the deduplicated canonical view."""

    async def _synthesize(self, state: SwarmGraphState) -> dict:
        # Mandatory report-only enrichment: every populated final report loads
        # this skill directly, including zero-finding reports whose coverage
        # limitations still need careful wording. It is intentionally absent
        # from the planner's dispatch surface because it is not a testing worker.
        skill = self.load_skill(REPORTING_SKILL_NAME)
        if skill is None:
            logger.warning("reporting skill is unavailable; using deterministic prose")
            return {}
        try:
            response = await self.ask_focused(
                f"{_SYNTHESIS_REQUEST}\n\n{synthesis_input(dict(state))}",
                system_prompt=skill.system_prompt,
                agent_id="reporting",
                run_id=str(state.get("run_id") or "") or None,
            )
            return parse_synthesis(response)
        except Exception as exc:  # noqa: BLE001
            # Reporting must remain available even if the final prose pass is
            # refused, times out, or returns invalid JSON.  Deterministic
            # category-aware fallbacks cover every required field.
            logger.warning(
                "reporting synthesis failed; using deterministic prose: %s: %s",
                type(exc).__name__, exc,
            )
            return {}

    async def execute(self, state: SwarmGraphState) -> dict:
        synthesis = await self._synthesize(state)
        report = build_report_content(dict(state), synthesis)
        markdown = render_markdown(report)
        artifact_fields: dict[str, str] = {
            "report_markdown": markdown,
            "report_markdown_path": "",
            "report_pdf_path": "",
            "report_pdf_error": "",
        }

        # Real-target runs seed one exact per-run output directory.  Persist
        # the lossless Markdown before rendering the PDF so a layout failure
        # can never destroy the complete report.
        output_value = str(state.get("output_dir") or "").strip()
        output_dir = Path(output_value).expanduser().resolve() if output_value else None
        pdf_output_path: Path | None = None
        if output_dir is not None:
            output_dir.mkdir(parents=True, exist_ok=True)
            artifact_prefix = str(state.get("artifact_prefix") or "").strip()
            report_stem = str(state.get("report_stem") or "").strip() or (
                f"{artifact_prefix} pentest report"
                if artifact_prefix
                else "pentest-report"
            )
            markdown_path = output_dir / f"{report_stem}.md"
            markdown_tmp = markdown_path.with_suffix(".md.tmp")
            markdown_tmp.write_text(markdown, encoding="utf-8")
            markdown_tmp.replace(markdown_path)
            artifact_fields["report_markdown_path"] = str(markdown_path)
            pdf_output_path = output_dir / f"{report_stem}.pdf"

        pdf_tmp: Path | None = None
        try:
            from src.reporting import generate_pentest_pdf

            if pdf_output_path is not None:
                pdf_tmp = pdf_output_path.with_suffix(".pdf.tmp")
                generate_pentest_pdf(
                    dict(state),
                    output_path=pdf_tmp,
                    report=report,
                )
                pdf_tmp.replace(pdf_output_path)
                artifact_fields["report_pdf_path"] = str(pdf_output_path)
            else:
                artifact_fields["report_pdf_path"] = str(
                    generate_pentest_pdf(dict(state), report=report)
                )
        except Exception as exc:  # noqa: BLE001
            if pdf_tmp is not None:
                pdf_tmp.unlink(missing_ok=True)
            logger.exception("Could not generate branded penetration-test PDF")
            artifact_fields["report_pdf_error"] = f"{type(exc).__name__}: {exc}"

        return {
            "messages": [HumanMessage(content=markdown)],
            **artifact_fields,
        }


report_node = ReportNode()
