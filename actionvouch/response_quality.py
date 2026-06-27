"""Evidence-first response-quality contract.

This is a self-contained, lightweight counterpart to the parent repo's
``ai_response_quality`` module. Every council output is held to the same
discipline: separate facts from assumptions from unknowns, attach evidence,
state risks and counterarguments, and *say when evidence is missing* rather
than filling the gap with confident language.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

# The structured sections every evidence-bearing council answer must carry.
REQUIRED_SECTIONS: tuple[str, ...] = (
    "Facts",
    "Assumptions",
    "Unknowns",
    "Confidence score",
    "Evidence",
    "Risks",
    "Counterarguments",
    "Recommendation",
    "Tradeoffs",
    "What would change the recommendation",
)

# The non-negotiable guardrails. The first is the load-bearing anti-fabrication
# rule that the evidence registry and runtime enforce in code.
BASE_GUARDRAILS: tuple[str, ...] = (
    "No council may fabricate missing data; if a dataset is missing, say it is missing.",
    "Separate verified facts from assumptions and from unknowns.",
    "Every material claim must cite attached evidence or be downgraded to an assumption.",
    "Do not assert outcomes, approvals, or readiness that the evidence does not support.",
    "Use a numeric confidence score between 0 and 1 and explain what limits it.",
    "List what evidence would change the recommendation.",
    "Do not make the answer more flattering; optimize for correctness over agreement.",
)


class ResponseMode(Enum):
    """How rigorous a council answer must be."""

    STANDARD_ANSWER = "standard_answer"
    EVIDENCE_BASED_ANSWER = "evidence_based_answer"
    EXECUTIVE_DECISION_MEMO = "executive_decision_memo"
    HOSTILE_RED_TEAM_REVIEW = "hostile_red_team_review"
    TECHNICAL_REVIEW = "technical_review"
    LEGAL_COMPLIANCE_RISK_REVIEW = "legal_compliance_risk_review"


_LABELS: dict[ResponseMode, str] = {
    ResponseMode.STANDARD_ANSWER: "Standard answer",
    ResponseMode.EVIDENCE_BASED_ANSWER: "Evidence-based answer",
    ResponseMode.EXECUTIVE_DECISION_MEMO: "Executive decision memo",
    ResponseMode.HOSTILE_RED_TEAM_REVIEW: "Hostile red-team review",
    ResponseMode.TECHNICAL_REVIEW: "Technical review",
    ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW: "Legal & compliance risk review",
}

_UI_LABELS: dict[ResponseMode, str] = {
    ResponseMode.STANDARD_ANSWER: "Standard Answer",
    ResponseMode.EVIDENCE_BASED_ANSWER: "Accuracy Mode",
    ResponseMode.EXECUTIVE_DECISION_MEMO: "CEO Review Mode",
    ResponseMode.HOSTILE_RED_TEAM_REVIEW: "Red Team Mode",
    ResponseMode.TECHNICAL_REVIEW: "Technical Review Mode",
    ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW: "Legal Risk Review Mode",
}

_MODE_HELP: dict[ResponseMode, str] = {
    ResponseMode.STANDARD_ANSWER: "Concise answer with evidence hygiene.",
    ResponseMode.EVIDENCE_BASED_ANSWER: "Separates facts, assumptions, unknowns, evidence, and confidence.",
    ResponseMode.EXECUTIVE_DECISION_MEMO: "Decision memo for owner or CEO review.",
    ResponseMode.HOSTILE_RED_TEAM_REVIEW: "Adversarial review that leads with failure modes.",
    ResponseMode.TECHNICAL_REVIEW: "Architecture, implementation, test, and operability review.",
    ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW: "Issue-spotting review; not legal advice or certification.",
}

_MODE_ALIASES: dict[str, ResponseMode] = {
    "standard": ResponseMode.STANDARD_ANSWER,
    "standard_answer": ResponseMode.STANDARD_ANSWER,
    "normal": ResponseMode.STANDARD_ANSWER,
    "accuracy": ResponseMode.EVIDENCE_BASED_ANSWER,
    "accuracy_mode": ResponseMode.EVIDENCE_BASED_ANSWER,
    "evidence": ResponseMode.EVIDENCE_BASED_ANSWER,
    "evidence_based": ResponseMode.EVIDENCE_BASED_ANSWER,
    "evidence_based_answer": ResponseMode.EVIDENCE_BASED_ANSWER,
    "honest_feedback": ResponseMode.EVIDENCE_BASED_ANSWER,
    "red_team": ResponseMode.HOSTILE_RED_TEAM_REVIEW,
    "red_team_mode": ResponseMode.HOSTILE_RED_TEAM_REVIEW,
    "hostile": ResponseMode.HOSTILE_RED_TEAM_REVIEW,
    "hostile_red_team": ResponseMode.HOSTILE_RED_TEAM_REVIEW,
    "hostile_red_team_review": ResponseMode.HOSTILE_RED_TEAM_REVIEW,
    "ceo": ResponseMode.EXECUTIVE_DECISION_MEMO,
    "ceo_review": ResponseMode.EXECUTIVE_DECISION_MEMO,
    "ceo_review_mode": ResponseMode.EXECUTIVE_DECISION_MEMO,
    "executive": ResponseMode.EXECUTIVE_DECISION_MEMO,
    "executive_memo": ResponseMode.EXECUTIVE_DECISION_MEMO,
    "executive_decision_memo": ResponseMode.EXECUTIVE_DECISION_MEMO,
    "technical": ResponseMode.TECHNICAL_REVIEW,
    "technical_review": ResponseMode.TECHNICAL_REVIEW,
    "technical_review_mode": ResponseMode.TECHNICAL_REVIEW,
    "architecture": ResponseMode.TECHNICAL_REVIEW,
    "legal": ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW,
    "legal_risk": ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW,
    "legal_risk_review": ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW,
    "legal_compliance": ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW,
    "legal_compliance_risk_review": ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW,
    "compliance": ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW,
}


def normalize_response_mode(value: object) -> ResponseMode:
    """Coerce arbitrary input into a :class:`ResponseMode`.

    Defaults to evidence-based — this tool defaults to evidence-based output, so
    the safe default is the rigorous mode, not the casual one.
    """

    if isinstance(value, ResponseMode):
        return value
    if isinstance(value, str):
        text = _alias_key(value)
        if text in _MODE_ALIASES:
            return _MODE_ALIASES[text]
        for mode in ResponseMode:
            if text == mode.value or text == mode.name.lower():
                return mode
    return ResponseMode.EVIDENCE_BASED_ANSWER


@dataclass(frozen=True)
class PromptTemplate:
    """A reusable prompt-template profile for response-quality enforcement."""

    template_id: str
    label: str
    mode: ResponseMode
    system_prompt: str
    developer_prompt: str
    required_sections: tuple[str, ...]
    guardrails: tuple[str, ...]
    output_rules: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "template_id": self.template_id,
            "label": self.label,
            "mode": self.mode.value,
            "system_prompt": self.system_prompt,
            "developer_prompt": self.developer_prompt,
            "required_sections": list(self.required_sections),
            "guardrails": list(self.guardrails),
            "output_rules": list(self.output_rules),
        }


@dataclass(frozen=True)
class QualityContract:
    """The quality bar attached to a council invocation."""

    mode: ResponseMode
    label: str
    required_sections: tuple[str, ...]
    guardrails: tuple[str, ...]
    output_rules: tuple[str, ...]
    prompt_templates: tuple[PromptTemplate, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode.value,
            "label": self.label,
            "ui_label": _UI_LABELS.get(self.mode, self.label),
            "required_sections": list(self.required_sections),
            "guardrails": list(self.guardrails),
            "output_rules": list(self.output_rules),
            "prompt_templates": [
                template.to_dict() for template in self.prompt_templates
            ],
        }


_OUTPUT_RULES: dict[ResponseMode, tuple[str, ...]] = {
    ResponseMode.STANDARD_ANSWER: (
        "Be concise, but keep facts, assumptions, unknowns, and confidence distinct.",
    ),
    ResponseMode.EVIDENCE_BASED_ANSWER: (
        "Lead with what is verified and what is missing.",
        "Do not recommend action without naming the evidence limits and tradeoffs.",
    ),
    ResponseMode.HOSTILE_RED_TEAM_REVIEW: (
        "Lead with the strongest case that the prior stage is wrong.",
        "Propose concrete falsification tests, not vague doubts.",
    ),
    ResponseMode.EXECUTIVE_DECISION_MEMO: (
        "Lead with the decision and its confidence.",
        "State the evidence status behind the decision explicitly.",
    ),
    ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW: (
        "Treat regulated, contractual, or claims exposure as a hard gate.",
        "Mark anything needing licensed human review as blocked_pending_human.",
        "State that the output is issue spotting, not legal advice or certification.",
    ),
    ResponseMode.TECHNICAL_REVIEW: (
        "Separate architecture facts from implementation assumptions.",
        "List test gaps, operational failure modes, and rollback concerns.",
    ),
}


def _template(
    template_id: str,
    label: str,
    mode: ResponseMode,
    system_prompt: str,
    developer_prompt: str,
    output_rules: tuple[str, ...],
) -> PromptTemplate:
    return PromptTemplate(
        template_id=template_id,
        label=label,
        mode=mode,
        system_prompt=system_prompt,
        developer_prompt=developer_prompt,
        required_sections=REQUIRED_SECTIONS,
        guardrails=BASE_GUARDRAILS,
        output_rules=output_rules,
    )


_PROMPT_TEMPLATES: tuple[PromptTemplate, ...] = (
    _template(
        "anti_hallucination_checks",
        "Anti-Hallucination Checks",
        ResponseMode.EVIDENCE_BASED_ANSWER,
        "You are an evidence gate. Do not let unsupported claims sound verified.",
        "Check each material claim against attached evidence. Move unsupported claims to assumptions or unknowns and lower confidence.",
        (
            "Say when evidence is missing.",
            "Reject invented facts, dates, citations, metrics, approvals, and test results.",
            "Use only attached evidence, prior stage outputs, source registry entries, or explicit user input.",
        ),
    ),
    _template(
        "red_team_review",
        "Red-Team Review",
        ResponseMode.HOSTILE_RED_TEAM_REVIEW,
        "You are the hostile reviewer. Your job is to find how the proposal fails.",
        "Lead with concrete failure modes, missing evidence, abuse paths, and falsification tests before any upside.",
        (
            "Lead with risks and blockers.",
            "Name the assumption most likely to be false.",
            "List tests that would disprove the recommendation.",
        ),
    ),
    _template(
        "ceo_reality_check",
        "CEO Reality Check",
        ResponseMode.EXECUTIVE_DECISION_MEMO,
        "You are preparing a reality check for an accountable owner.",
        "State the decision, evidence status, confidence, cost of being wrong, and next reversible action.",
        (
            "Lead with the decision and confidence.",
            "Separate ready-now action from blocked or speculative action.",
            "List the decision evidence that would change the answer.",
        ),
    ),
    _template(
        "evidence_based_recommendations",
        "Evidence-Based Recommendations",
        ResponseMode.EVIDENCE_BASED_ANSWER,
        "You are a recommendation engine constrained by evidence.",
        "Recommend only what the evidence supports and describe tradeoffs, counterarguments, and change conditions.",
        (
            "State the recommendation only after facts, assumptions, unknowns, and risks.",
            "Include tradeoffs for every material recommendation.",
        ),
    ),
    _template(
        "legal_compliance_review",
        "Legal/Compliance Review",
        ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW,
        "You are doing issue spotting for legal and compliance exposure.",
        "Identify claim, privacy, regulatory, contractual, and approval risks. Do not provide legal advice or certification.",
        (
            "Use non-attorney caveats for legal or compliance conclusions.",
            "Mark missing counsel, assessor, or owner review as a blocker when material.",
            "Do not say compliant, certified, legal-safe, or approved unless evidence proves it.",
        ),
    ),
    _template(
        "technical_architecture_review",
        "Technical Architecture Review",
        ResponseMode.TECHNICAL_REVIEW,
        "You are reviewing architecture and implementation risk.",
        "Separate verified behavior from design assumptions, list failure modes, and identify test and rollback gaps.",
        (
            "List architecture facts before opinions.",
            "Name operational risks, observability gaps, and test gaps.",
            "Identify what would need to pass before production use.",
        ),
    ),
    _template(
        "bias_detection",
        "Bias Detection",
        ResponseMode.EVIDENCE_BASED_ANSWER,
        "You are checking for bias, unfairness, and overgeneralization.",
        "Identify affected groups, missing demographic or workflow evidence, proxy variables, and overbroad conclusions.",
        (
            "Do not infer protected-class or demographic facts without evidence.",
            "List where evidence is insufficient to assess bias.",
            "Recommend safer review steps when bias cannot be ruled out.",
        ),
    ),
    _template(
        "executive_decision_matrix",
        "Executive Decision Matrix",
        ResponseMode.EXECUTIVE_DECISION_MEMO,
        "You are building an executive decision matrix.",
        "Compare options using evidence, reversibility, risk, cost, confidence, and what would change the decision.",
        (
            "Compare at least proceed, pause, and gather-evidence options when relevant.",
            "State the reversible next step separately from the long-term bet.",
        ),
    ),
)

_TEMPLATES_BY_MODE: dict[ResponseMode, tuple[str, ...]] = {
    ResponseMode.STANDARD_ANSWER: (
        "anti_hallucination_checks",
        "evidence_based_recommendations",
    ),
    ResponseMode.EVIDENCE_BASED_ANSWER: (
        "anti_hallucination_checks",
        "evidence_based_recommendations",
        "bias_detection",
    ),
    ResponseMode.HOSTILE_RED_TEAM_REVIEW: (
        "anti_hallucination_checks",
        "red_team_review",
    ),
    ResponseMode.EXECUTIVE_DECISION_MEMO: (
        "anti_hallucination_checks",
        "ceo_reality_check",
        "executive_decision_matrix",
    ),
    ResponseMode.TECHNICAL_REVIEW: (
        "anti_hallucination_checks",
        "technical_architecture_review",
    ),
    ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW: (
        "anti_hallucination_checks",
        "legal_compliance_review",
    ),
}

_TEMPLATE_BY_ID = {template.template_id: template for template in _PROMPT_TEMPLATES}


def build_quality_contract(mode: ResponseMode) -> QualityContract:
    """Return the quality contract for a response mode."""

    templates = prompt_templates_for_mode(mode)
    return QualityContract(
        mode=mode,
        label=_LABELS.get(mode, mode.value),
        required_sections=REQUIRED_SECTIONS,
        guardrails=BASE_GUARDRAILS,
        output_rules=_dedupe_tuple(
            [
                *_OUTPUT_RULES.get(mode, ()),
                *(rule for template in templates for rule in template.output_rules),
            ]
        ),
        prompt_templates=templates,
    )


def build_response_skeleton(
    mode: ResponseMode, *, evidence_available: bool = True
) -> dict[str, object]:
    """Return an empty, section-keyed answer skeleton for a response mode."""

    sections: dict[str, list[str]] = {section: [] for section in REQUIRED_SECTIONS}
    if not evidence_available:
        sections["Unknowns"] = [
            "Required evidence was not attached; conclusions are provisional."
        ]
    return {
        "mode": mode.value,
        "mode_label": _LABELS.get(mode, mode.value),
        "evidence_available": evidence_available,
        "sections": sections,
    }


def all_prompt_templates() -> tuple[PromptTemplate, ...]:
    """Return every reusable response-quality prompt template."""

    return _PROMPT_TEMPLATES


def prompt_templates_for_mode(mode: ResponseMode) -> tuple[PromptTemplate, ...]:
    """Return the prompt templates that apply to a response mode."""

    template_ids = _TEMPLATES_BY_MODE.get(mode, ("anti_hallucination_checks",))
    return tuple(_TEMPLATE_BY_ID[template_id] for template_id in template_ids)


def response_mode_options(*, include_standard: bool = True) -> list[dict[str, str]]:
    """Return UI/CLI display metadata for response mode selection."""

    modes = [
        ResponseMode.STANDARD_ANSWER,
        ResponseMode.EVIDENCE_BASED_ANSWER,
        ResponseMode.HOSTILE_RED_TEAM_REVIEW,
        ResponseMode.EXECUTIVE_DECISION_MEMO,
        ResponseMode.TECHNICAL_REVIEW,
        ResponseMode.LEGAL_COMPLIANCE_RISK_REVIEW,
    ]
    if not include_standard:
        modes = [mode for mode in modes if mode != ResponseMode.STANDARD_ANSWER]
    return [
        {
            "value": mode.value,
            "label": _LABELS[mode],
            "ui_label": _UI_LABELS[mode],
            "help": _MODE_HELP[mode],
        }
        for mode in modes
    ]


def response_mode_aliases() -> dict[str, str]:
    """Return accepted user-facing aliases for response modes."""

    return {alias: mode.value for alias, mode in sorted(_MODE_ALIASES.items())}


def _alias_key(value: str) -> str:
    return value.strip().lower().replace("-", "_").replace(" ", "_").replace("/", "_")


def _dedupe_tuple(values: list[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return tuple(output)
