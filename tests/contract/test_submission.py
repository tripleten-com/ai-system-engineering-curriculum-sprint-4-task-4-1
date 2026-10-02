"""Coldline.

===================

File:              tests/contract/test_submission.py
Component:         Contract tests — Test Submission
Purpose:           Tests for the public answer, threat-model, and path checks for this Task.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest
"""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.contract import threat_model
from tests.contract.submission_validation import (
    SubmissionError,
    _load_one_document,
    main,
    validate_changed_paths,
    validate_submission,
    validate_threat_model,
)

ROOT = Path(__file__).parents[2]
SCHEMA = ROOT / "docs/contracts/submission.schema.json"
# The blank template as shipped, kept as a fixture: docs/student/threat-model.md is the
# student's to complete, so these tests never read it, not even to compare. The assessed
# checks in test_threat_model.py are the only tests that read the student's own file.
# That the fixture equals the shipped template is an authoring invariant of the source
# layer, checked where the layer lives, not in the exported repository.
TEMPLATE = ROOT / "tests/fixtures/threat-model-template.md"
TRACE_ID = "0123456789abcdef0123456789abcdef"


def valid_answers(**overrides: Any) -> dict[str, object]:
    """Return a complete answer sheet in the published shape.

    Fictional format example: these values show the shape and state no result.
    They are deliberately not a reading of the code, so copying them answers
    nothing.
    """
    threats = threat_model.threat_ids()
    answers: dict[str, Any] = {
        "boundary_flows": ["DF-02", "DF-03"],
        "threat_categories": {identifier: "tampering" for identifier in threats},
        "likelihood": {identifier: "low" for identifier in threats},
        "top_threats": ["TH-02", "TH-04", "TH-08", "TH-10", "TH-12"],
        "control_scope": {
            "TH-02": "C-07",
            "TH-04": "C-08",
            "TH-08": "C-10",
            "TH-10": "C-03",
            "TH-12": "C-06",
        },
    }
    answers.update(overrides)
    return {"answers": answers}


def _task_root(tmp_path: Path, submission_text: str) -> Path:
    """Stage a minimal Task root the public verifier can validate."""
    (tmp_path / "docs/contracts").mkdir(parents=True)
    (tmp_path / "docs/student").mkdir(parents=True)
    (tmp_path / "submission.yaml").write_text(submission_text, encoding="utf-8")
    (tmp_path / "submission-sample.yaml").write_text(
        (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs/contracts/submission.schema.json").write_text(
        SCHEMA.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs/student/threat-model.md").write_text(
        TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return tmp_path


def _completed_threat_model(top_threats: list[str]) -> str:
    """Return a structurally complete threat model for the given ranking.

    The prose is filler: these checks never read it. Only the shape matters,
    which is why the text says so.
    """
    second = "\n".join(
        f"- {identifier}: src/example.py, a filler basis for the structure check."
        for identifier in threat_model.threat_ids()
    )
    third = "\n\n".join(
        f"### Rank {rank}: {identifier}\n\nA filler abuse case for the structure check."
        for rank, identifier in enumerate(top_threats, start=1)
    )
    return (
        "# Threat model\n\n"
        f"{threat_model.REQUIRED_HEADINGS[0]}\n\n"
        f"Trace id followed: {TRACE_ID}\n\n"
        "- DF-02: filler trust difference for the structure check.\n\n"
        f"{threat_model.REQUIRED_HEADINGS[1]}\n\n{second}\n\n"
        f"{threat_model.REQUIRED_HEADINGS[2]}\n\n{third}\n\n"
        f"{threat_model.REQUIRED_HEADINGS[3]}\n\n"
        "A filler omission for the structure check.\n"
    )


def test_a_complete_sheet_is_well_formed(tmp_path: Path) -> None:
    """The public schema accepts a complete sheet without judging its correctness."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers()))

    validate_submission(root / "submission.yaml", SCHEMA)


def test_blank_template_fails_with_field_address(tmp_path: Path) -> None:
    """An untouched answer sheet must identify the first incomplete field."""
    root = _task_root(
        tmp_path, (ROOT / "tests/fixtures/submission-template.yaml").read_text(encoding="utf-8")
    )

    with pytest.raises(SubmissionError, match="answers.boundary_flows"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"boundary_flows": ["DF-99"]}, "boundary_flows"),
        ({"boundary_flows": ["DF-02", "DF-02"]}, "boundary_flows"),
        ({"threat_categories": {"TH-01": "tampering"}}, "threat_categories"),
        ({"likelihood": {"TH-01": "certain"}}, "likelihood"),
        ({"top_threats": ["TH-02", "TH-04", "TH-08", "TH-10"]}, "top_threats"),
        ({"top_threats": ["TH-02", "TH-04", "TH-08", "TH-10", "TH-10"]}, "top_threats"),
        ({"control_scope": {"TH-02": "C-99"}}, "control_scope"),
    ],
    ids=[
        "unknown-flow",
        "repeated-flow",
        "missing-threats",
        "unlisted-likelihood",
        "four-threats",
        "repeated-threat",
        "unknown-control",
    ],
)
def test_values_outside_the_published_contract_are_rejected(
    tmp_path: Path, overrides: dict[str, Any], message: str
) -> None:
    """The public schema must name the field it rejected, and reject the right ones."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers(**overrides)))

    with pytest.raises(SubmissionError, match=message):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_a_category_outside_stride_is_rejected(tmp_path: Path) -> None:
    """A nested value outside the six STRIDE names cannot hide behind a complete sheet."""
    categories = dict(valid_answers()["answers"]["threat_categories"])  # type: ignore[index]
    categories["TH-03"] = "injection"
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers(threat_categories=categories)))

    with pytest.raises(SubmissionError, match="TH-03"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_a_blank_nested_value_is_rejected(tmp_path: Path) -> None:
    """A nested placeholder cannot hide behind the top-level placeholder check."""
    likelihood = dict(valid_answers()["answers"]["likelihood"])  # type: ignore[index]
    likelihood["TH-05"] = ""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers(likelihood=likelihood)))

    with pytest.raises(SubmissionError, match="TH-05"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_control_scope_must_be_keyed_by_the_ranked_threats(tmp_path: Path) -> None:
    """A control for a threat outside the top five, or a missing one, is a format error."""
    scope = {"TH-02": "C-07", "TH-04": "C-08", "TH-08": "C-10", "TH-10": "C-03", "TH-13": "C-11"}
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers(control_scope=scope)))

    with pytest.raises(SubmissionError, match="exactly the five threats"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "field",
    ["threats_reviewed", "instructor_approved", "defense_recording_url", "notes"],
)
def test_no_self_attestation_or_recording_field_is_accepted(tmp_path: Path, field: str) -> None:
    """Reject a self-approval, a pass boolean, or a recording URL."""
    answers = valid_answers()
    mapping = answers["answers"]
    assert isinstance(mapping, dict)
    mapping[field] = True
    root = _task_root(tmp_path, yaml.safe_dump(answers))

    with pytest.raises(SubmissionError, match="Additional properties"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_exact_sample_copy_is_rejected(tmp_path: Path) -> None:
    """The published sample must not be accepted as a student submission."""
    root = _task_root(tmp_path, (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"))

    with pytest.raises(SubmissionError, match="fictional sample"):
        validate_submission(
            root / "submission.yaml",
            SCHEMA,
            sample_path=root / "submission-sample.yaml",
        )


def test_only_the_two_permitted_paths_may_change() -> None:
    """The answer sheet and the threat model; nothing else."""
    validate_changed_paths(["submission.yaml", "docs/student/threat-model.md"])

    for protected in (
        "docs/security/workflow.md",
        "docs/security/threat-catalog.yaml",
        "docs/security/scoring.md",
        "docs/security/control-matrix.md",
        "src/api/routes.py",
        "src/worker/use_cases.py",
        "tests/contract/threat_model.py",
        ".github/workflows/task.yml",
        "compose.yaml",
        "pyproject.toml",
        "README.md",
    ):
        with pytest.raises(SubmissionError, match="protected path changed"):
            validate_changed_paths([protected])


def test_template_fixture_is_the_blank_template_with_its_headings_and_markers() -> None:
    """The fixture is a blank template: four headings in order, every marker in place.

    This reads the fixture only. The student's `docs/student/threat-model.md`
    is theirs to edit, in any order and in part, so no non-assessed check
    reads it: a half-completed file must not fail `poe contract`.
    """
    text = TEMPLATE.read_text(encoding="utf-8")
    visible = threat_model._COMMENT.sub("", text)

    assert threat_model.remaining_markers(text) == list(threat_model.TEMPLATE_MARKERS)
    positions = [visible.index(heading) for heading in threat_model.REQUIRED_HEADINGS]
    assert positions == sorted(positions)


def test_supplied_threat_model_template_fails_the_structure_check() -> None:
    """The untouched template is rejected for its markers, its trace id, and its abuse cases.

    The template scaffolds one line per catalog threat and a last section, each
    carrying a marker, so those two checks are satisfied structurally and the
    marker check is what fails them.
    """
    findings = threat_model.findings(TEMPLATE, top_threats=("TH-02",))

    assert [finding for finding in findings if "template marker" in finding] == [
        f"template marker still present: {marker!r}" for marker in threat_model.TEMPLATE_MARKERS
    ]
    assert any("trace id" in finding for finding in findings)
    assert any("has no abuse case for TH-02" in finding for finding in findings)


def test_a_section_left_empty_is_named(tmp_path: Path) -> None:
    """A last section with its marker removed and nothing written is a finding."""
    top = ["TH-02", "TH-04", "TH-08", "TH-10", "TH-12"]
    text = _completed_threat_model(top).replace("A filler omission for the structure check.\n", "")
    path = tmp_path / "threat-model.md"
    path.write_text(text, encoding="utf-8")

    findings = threat_model.findings(path, top_threats=tuple(top))

    assert findings == ["'## 4. What this model leaves out' has no content of its own"]


def test_a_structurally_complete_threat_model_passes(tmp_path: Path) -> None:
    """The structure check accepts a filled-in model without reading its prose."""
    top = ["TH-02", "TH-04", "TH-08", "TH-10", "TH-12"]
    path = tmp_path / "threat-model.md"
    path.write_text(_completed_threat_model(top), encoding="utf-8")

    assert threat_model.findings(path, top_threats=tuple(top)) == []
    validate_threat_model(path, valid_answers(top_threats=top))


def test_one_marker_left_in_an_abuse_case_is_the_only_finding(tmp_path: Path) -> None:
    """A model complete but for one placeholder fails the marker check and nothing else."""
    top = ["TH-02", "TH-04", "TH-08", "TH-10", "TH-12"]
    text = _completed_threat_model(top).replace(
        "### Rank 3: TH-08\n\nA filler abuse case for the structure check.",
        "### Rank 3: TH-08\n\n_Write your evidence here._",
    )
    path = tmp_path / "threat-model.md"
    path.write_text(text, encoding="utf-8")

    findings = threat_model.findings(path, top_threats=tuple(top))

    assert findings == ["template marker still present: '_Write your evidence here._'"]


def test_a_missing_abuse_case_is_named(tmp_path: Path) -> None:
    """Removing one ranked threat's abuse-case block is reported by that threat's id."""
    top = ["TH-02", "TH-04", "TH-08", "TH-10", "TH-12"]
    text = _completed_threat_model(top).replace(
        "### Rank 3: TH-08\n\nA filler abuse case for the structure check.\n\n", ""
    )
    path = tmp_path / "threat-model.md"
    path.write_text(text, encoding="utf-8")

    findings = threat_model.findings(path, top_threats=tuple(top))

    assert findings == ["'## 3. Abuse cases' has no abuse case for TH-08"]


def test_an_abuse_case_heading_naming_several_threats_counts_for_none(tmp_path: Path) -> None:
    """One heading listing several ranked ids over one paragraph is an entry for none of them."""
    top = ["TH-02", "TH-04", "TH-08", "TH-10", "TH-12"]
    text = _completed_threat_model(top).replace(
        "### Rank 2: TH-04\n\nA filler abuse case for the structure check.\n\n"
        "### Rank 3: TH-08\n\nA filler abuse case for the structure check.",
        "### Ranks 2 and 3: TH-04 and TH-08\n\nA filler abuse case for the structure check.",
    )
    path = tmp_path / "threat-model.md"
    path.write_text(text, encoding="utf-8")

    findings = threat_model.findings(path, top_threats=tuple(top))

    assert findings == [
        "'## 3. Abuse cases' has no abuse case for TH-04",
        "'## 3. Abuse cases' has no abuse case for TH-08",
    ]


def test_a_likelihood_line_naming_several_threats_counts_for_none(tmp_path: Path) -> None:
    """One section-2 line naming two catalog ids is a line of its own for neither."""
    top = ["TH-02", "TH-04", "TH-08", "TH-10", "TH-12"]
    text = _completed_threat_model(top).replace(
        "- TH-05: src/example.py, a filler basis for the structure check.\n"
        "- TH-06: src/example.py, a filler basis for the structure check.\n",
        "- TH-05, TH-06: src/example.py, a filler basis for the structure check.\n",
    )
    path = tmp_path / "threat-model.md"
    path.write_text(text, encoding="utf-8")

    findings = threat_model.findings(path, top_threats=tuple(top))

    assert findings == [
        "'## 2. Likelihood basis' has no line of its own for TH-05",
        "'## 2. Likelihood basis' has no line of its own for TH-06",
    ]


def test_a_reordered_heading_is_named(tmp_path: Path) -> None:
    """The four sections must keep the supplied order."""
    top = ["TH-02", "TH-04", "TH-08", "TH-10", "TH-12"]
    text = _completed_threat_model(top)
    first, second = threat_model.REQUIRED_HEADINGS[:2]
    swapped = text.replace(first, "@@").replace(second, first).replace("@@", second)
    path = tmp_path / "threat-model.md"
    path.write_text(swapped, encoding="utf-8")

    findings = threat_model.findings(path, top_threats=tuple(top))

    assert len(findings) == 1 and "out of order" in findings[0]


def test_public_entrypoint_reports_an_incomplete_answer_sheet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catch a verifier entrypoint that skips the real submission contract."""
    root = _task_root(
        tmp_path, (ROOT / "tests/fixtures/submission-template.yaml").read_text(encoding="utf-8")
    )

    assert main(root, changed_paths=[], format_only=True) == 1
    assert "answers.boundary_flows is incomplete" in capsys.readouterr().err


def test_format_only_entrypoint_accepts_a_complete_sheet_with_the_untouched_template(
    tmp_path: Path,
) -> None:
    """`poe answers` checks the sheet's format and nothing about the threat model."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers()))

    assert main(root, changed_paths=[], format_only=True) == 0


def test_public_entrypoint_rejects_an_untouched_threat_model(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A complete answer sheet with the template model still in place is incomplete."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers()))

    assert main(root, changed_paths=[]) == 1
    assert "template marker" in capsys.readouterr().err


def test_public_entrypoint_accepts_a_complete_pair(tmp_path: Path) -> None:
    """A well-formed sheet and a structurally complete model pass the whole public path."""
    top = ["TH-02", "TH-04", "TH-08", "TH-10", "TH-12"]
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers(top_threats=top)))
    (root / "docs/student/threat-model.md").write_text(
        _completed_threat_model(top), encoding="utf-8"
    )

    assert main(root, changed_paths=["submission.yaml", "docs/student/threat-model.md"]) == 0


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "answers: {value: first, value: second}\n",
        "answers: &answer {value: fictional}\n",
        "answers: *missing\n",
        "answers: {<<: {value: fictional}}\n",
        "answers: {value: 2026-09-04}\n",
        "answers: {value: !custom fictional}\n",
        "answers: {1: fictional}\n",
    ],
    ids=["duplicate-key", "anchor", "alias", "merge-key", "date", "custom-tag", "non-string-key"],
)
def test_non_json_yaml_constructs_are_rejected(tmp_path: Path, unsafe_text: str) -> None:
    """Reject restricted syntax before schema validation can mask a parser defect."""
    submission = tmp_path / "submission.yaml"
    submission.write_text(unsafe_text, encoding="utf-8")

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_multiple_yaml_documents_are_rejected(tmp_path: Path) -> None:
    """A second document cannot supply or replace the answer mapping."""
    submission = tmp_path / "submission.yaml"
    submission.write_text("answers: {}\n---\nanswers: {}\n", encoding="utf-8")

    with pytest.raises(SubmissionError, match="exactly one YAML mapping"):
        _load_one_document(submission)


def test_a_sheet_that_is_not_utf_8_is_a_submission_error(tmp_path: Path) -> None:
    """A sheet saved in another encoding gets the public error, not a Python traceback."""
    submission = tmp_path / "submission.yaml"
    submission.write_bytes("answers: {boundary_flows: [DF-01]}\n".encode("utf-16"))

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def _enum(schema: dict[str, Any], node: dict[str, Any]) -> tuple[str, ...]:
    """Return a node's enum, following one local `$ref` into the schema's `$defs`."""
    reference = node.get("$ref")
    if isinstance(reference, str):
        node = schema["$defs"][reference.rsplit("/", maxsplit=1)[-1]]
    return tuple(node["enum"])


def test_supplied_security_material_and_the_schema_name_the_same_ids() -> None:
    """The workflow, the catalog, the matrix, and the schema agree on every id."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    answers = schema["properties"]["answers"]["properties"]
    flows = _enum(schema, answers["boundary_flows"]["items"])
    threats = _enum(schema, answers["top_threats"]["items"])
    controls = _enum(schema, answers["control_scope"]["additionalProperties"])

    assert flows == threat_model.flow_ids()
    assert threats == threat_model.threat_ids()
    assert controls == threat_model.control_ids()
    assert tuple(answers["threat_categories"]["required"]) == threats
    assert tuple(answers["likelihood"]["required"]) == threats
    assert _enum(schema, answers["control_scope"]["propertyNames"]) == threats
    for identifier in threats:
        categories = _enum(schema, answers["threat_categories"]["properties"][identifier])
        assert categories == threat_model.STRIDE_CATEGORIES
        scale = _enum(schema, answers["likelihood"]["properties"][identifier])
        assert scale == threat_model.LIKELIHOOD_SCALE
