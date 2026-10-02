"""Coldline.

===================

File:              tests/contract/test_threat_model.py
Component:         Contract tests — Threat model
Purpose:           One assessed check per public Check-list row, over this repository's own
                    submission.yaml and docs/student/threat-model.md.
Interacts With:    submission.yaml, docs/student/threat-model.md, docs/security/*
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Threat model, deterministic assessment, structure not prose
Tools:             Python 3.12, pytest

Assessed, not runtime: no stack is needed, and a fresh starter has a blank
answer sheet and the untouched template, so every test here is expected to
fail until the student completes both files. `poe contract` deselects them;
`poe threat-model-contract` and `poe verify` run them. None judges which flows,
categories, likelihoods, threats, or controls were chosen: the protected answer
check does that after the submission on the platform.
"""

from pathlib import Path

import pytest

from tests.contract import threat_model
from tests.contract.submission_validation import (
    SubmissionError,
    _load_one_document,
    validate_submission,
)

TASK_ROOT = Path(__file__).resolve().parents[2]
SUBMISSION = TASK_ROOT / "submission.yaml"
SCHEMA = TASK_ROOT / "docs/contracts/submission.schema.json"
pytestmark = pytest.mark.assessed


def _answers() -> dict[str, object]:
    """Return the answers mapping of this repository's own sheet."""
    answers = _load_one_document(SUBMISSION).get("answers")
    assert isinstance(answers, dict), "answers must be one mapping"
    return answers


def _ranked() -> tuple[str, ...]:
    """Return the student's ranked threat ids as a tuple of strings."""
    top = _answers().get("top_threats")
    assert isinstance(top, list), "answers.top_threats must be a list"
    return tuple(identifier for identifier in top if isinstance(identifier, str))


def _section_findings(prefix: str) -> list[str]:
    """Return the structural findings that name one section."""
    return [
        finding
        for finding in threat_model.findings(top_threats=_ranked())
        if finding.startswith(prefix)
    ]


def test_every_boundary_flow_is_a_flow_in_the_workflow() -> None:
    """Every id in `answers.boundary_flows` is a flow in `docs/security/workflow.md`."""
    flows = _answers().get("boundary_flows")
    assert isinstance(flows, list) and flows, "answers.boundary_flows must list at least one flow"
    unknown = sorted(set(flows) - set(threat_model.flow_ids()))
    assert not unknown, f"not flows in docs/security/workflow.md: {unknown}"


def test_every_catalog_threat_has_one_stride_category() -> None:
    """Every threat in the catalog has one STRIDE category in `answers.threat_categories`."""
    categories = _answers().get("threat_categories")
    assert isinstance(categories, dict)
    for identifier in threat_model.threat_ids():
        assert categories.get(identifier) in threat_model.STRIDE_CATEGORIES, identifier


def test_every_catalog_threat_has_one_likelihood_from_the_scale() -> None:
    """Every threat has one likelihood in `answers.likelihood` from the scale in scoring.md."""
    likelihood = _answers().get("likelihood")
    assert isinstance(likelihood, dict)
    for identifier in threat_model.threat_ids():
        assert likelihood.get(identifier) in threat_model.LIKELIHOOD_SCALE, identifier


def test_top_threats_lists_five_catalog_ids_in_rank_order() -> None:
    """`answers.top_threats` lists five distinct catalog ids.

    Rank order is an ordered list, which this check keeps; whether the order
    follows the scoring rule is the protected answer check's question.
    """
    ranked = _ranked()
    assert len(ranked) == 5, "answers.top_threats must list exactly five threats"
    assert len(set(ranked)) == 5, "answers.top_threats must not repeat a threat"
    unknown = sorted(set(ranked) - set(threat_model.threat_ids()))
    assert not unknown, f"not threats in docs/security/threat-catalog.yaml: {unknown}"


def test_each_top_threat_has_one_control_from_the_matrix() -> None:
    """Each threat in `answers.top_threats` has one control id from the matrix."""
    scope = _answers().get("control_scope")
    assert isinstance(scope, dict)
    assert len(scope) == 5, "answers.control_scope must hold one control per top threat"
    assert set(scope) == set(_ranked()), "answers.control_scope must be keyed by the top five"
    controls = set(threat_model.control_ids())
    for identifier, control in scope.items():
        assert control in controls, f"{identifier}: {control!r} is not in the control matrix"


def test_submission_passes_the_public_answer_format_check() -> None:
    """`submission.yaml` passes the public answer-format check."""
    try:
        validate_submission(
            SUBMISSION,
            SCHEMA,
            sample_path=TASK_ROOT / "submission-sample.yaml",
            task_root=TASK_ROOT,
        )
    except SubmissionError as exc:
        pytest.fail(str(exc))


def test_threat_model_replaces_every_template_marker() -> None:
    """`docs/student/threat-model.md` replaces every template marker."""
    text = threat_model.THREAT_MODEL_PATH.read_text(encoding="utf-8")
    assert threat_model.remaining_markers(text) == []


def test_first_section_names_the_trace_id_followed() -> None:
    """The first section of the threat model names the trace id followed."""
    findings = _section_findings(f"{threat_model.REQUIRED_HEADINGS[0]!r}")
    assert findings == [], "; ".join(findings)


def test_second_section_has_a_line_for_each_catalog_threat() -> None:
    """The second section names the file and behavior behind each likelihood, one per threat."""
    findings = _section_findings(f"{threat_model.REQUIRED_HEADINGS[1]!r}")
    assert findings == [], "; ".join(findings)


def test_third_section_has_an_abuse_case_for_each_top_threat() -> None:
    """The third section has an abuse case for each of the five top threats."""
    assert len(_ranked()) == 5, "answers.top_threats must list five threats first"
    findings = _section_findings(f"{threat_model.REQUIRED_HEADINGS[2]!r}")
    assert findings == [], "; ".join(findings)


def test_last_section_names_what_the_model_leaves_out() -> None:
    """The last section names at least one threat or boundary the model leaves out."""
    findings = _section_findings(f"{threat_model.REQUIRED_HEADINGS[3]!r}")
    assert findings == [], "; ".join(findings)


def test_threat_model_keeps_its_four_sections_in_order() -> None:
    """The four supplied headings are present, once each, in the supplied order."""
    findings = [
        finding
        for finding in threat_model.findings(top_threats=_ranked())
        if "required heading" in finding
    ]
    assert findings == [], "; ".join(findings)
