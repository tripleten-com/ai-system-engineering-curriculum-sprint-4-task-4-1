"""Coldline.

===================

File:              tests/contract/submission_validation.py
Component:         Contract tests — Submission Validation
Purpose:           Validate Task 4.1 answers, the threat model's structure, and the permitted paths.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest

Two entrypoints share this module. ``poe answers`` runs it with ``--format-only``
and checks the answer sheet's format alone: the YAML profile, the published
schema, and that the control scope names exactly the five ranked threats.
``poe verify`` runs it in full, which adds the permitted-path boundary, the
template-marker check on ``docs/student/threat-model.md``, and that file's
structural checks. Neither judges which flows, categories, likelihoods,
threats, or controls the student chose: that is the protected answer check's
job, after the submission on the platform.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator

# Task 4.1's pull request changes the answer sheet and the threat model, and
# nothing else: the supplied security material, the application code, the
# tests, and the workflows stay as supplied.
ALLOWED_PATHS = frozenset({"submission.yaml", "docs/student/threat-model.md"})
ALLOWED_PREFIXES: tuple[str, ...] = ()
THREAT_MODEL_PATH = "docs/student/threat-model.md"


_JSON_YAML_TAGS = frozenset(
    {
        "tag:yaml.org,2002:map",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
    }
)


class _RestrictedYamlLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Load the Task's small YAML profile without YAML-only conveniences."""

    def compose_node(self, parent: object, index: object) -> yaml.Node:
        # A prior anchor is already rejected below, but deny aliases directly too.
        if self.check_event(yaml.AliasEvent):
            event = self.get_event()
            raise yaml.composer.ComposerError(
                None,
                None,
                "YAML aliases are not permitted",
                event.start_mark,
            )
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise yaml.composer.ComposerError(
                None,
                None,
                "YAML anchors are not permitted",
                event.start_mark,
            )
        return super().compose_node(parent, index)

    def construct_object(self, node: yaml.Node, deep: bool = False) -> object:
        if node.tag not in _JSON_YAML_TAGS:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                "non-JSON YAML tags are not permitted",
                node.start_mark,
            )
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, object]:
        mapping: dict[str, object] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML merge keys are not permitted",
                    key_node.start_mark,
                )
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML mapping keys must be strings",
                    key_node.start_mark,
                )
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    f"duplicate YAML key: {key}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


class SubmissionError(ValueError):
    """Report one actionable public-verification failure."""


def main(
    root: Path | None = None,
    *,
    changed_paths: list[str] | None = None,
    format_only: bool = False,
) -> int:
    """Validate the answer sheet, and unless ``format_only``, the threat model and the diff.

    The optional arguments keep this entrypoint testable without changing the
    process working directory or creating a temporary Git repository.
    """
    task_root = Path.cwd() if root is None else root
    try:
        validate_submission(
            task_root / "submission.yaml",
            task_root / "docs/contracts/submission.schema.json",
            sample_path=task_root / "submission-sample.yaml",
            task_root=task_root,
        )
        if not format_only:
            validate_threat_model(
                task_root / THREAT_MODEL_PATH, _load_one_document(task_root / "submission.yaml")
            )
            validate_changed_paths(
                _changed_paths(task_root) if changed_paths is None else changed_paths
            )
    except (SubmissionError, RuntimeError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    if format_only:
        print("Task 4.1 answer format check passed.")
    else:
        print("Task 4.1 answer, threat model, and permitted-path verification passed.")
    return 0


def validate_submission(
    submission_path: Path,
    schema_path: Path,
    *,
    sample_path: Path | None = None,
    task_root: Path | None = None,
) -> None:
    """Validate YAML shape, placeholders, schema, answer consistency, and sample-copy behavior.

    ``task_root`` names the repository that owns the supplied security
    material. It defaults to the answer sheet's own directory, which is
    correct for a student checkout. A curriculum-owned evaluator validating a
    reference sheet stored elsewhere passes the trusted Task root explicitly.
    """
    submission = _load_one_document(submission_path)
    answers = submission.get("answers") if isinstance(submission, dict) else None
    if not isinstance(answers, dict):
        raise SubmissionError("answers must be one mapping")

    for field, value in answers.items():
        if isinstance(value, str) and (not value.strip() or "Replace this line" in value):
            raise SubmissionError(f"answers.{field} is incomplete")
        if isinstance(value, list | dict) and not value:
            raise SubmissionError(f"answers.{field} is incomplete")
        if isinstance(value, dict):
            for nested, nested_value in value.items():
                if isinstance(nested_value, str) and not nested_value.strip():
                    raise SubmissionError(f"answers.{field}.{nested} is incomplete")

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(submission), key=lambda error: list(error.path)
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "submission"
        raise SubmissionError(f"{location}: {error.message}")

    # The schema fixes each field's shape; this is the one relation it cannot
    # state: the control scope is keyed by exactly the five ranked threats.
    top_threats = answers.get("top_threats")
    control_scope = answers.get("control_scope")
    if isinstance(top_threats, list) and isinstance(control_scope, dict):
        if set(control_scope) != set(top_threats):
            raise SubmissionError(
                "answers.control_scope must name exactly the five threats in answers.top_threats"
            )

    if sample_path is not None and submission == _load_one_document(sample_path):
        raise SubmissionError("submission must not copy the fictional sample answers")


def validate_threat_model(path: Path, submission: dict[str, Any]) -> None:
    """Reject a threat model with a template marker left or a section without its entries."""
    # Imported here, not at module level: ci_proof.py loads this module in isolation
    # (runpy, without the Task root on sys.path) and calls only validate_changed_paths.
    from tests.contract import threat_model

    answers = submission.get("answers")
    top_threats = answers.get("top_threats") if isinstance(answers, dict) else None
    ranked = tuple(
        identifier
        for identifier in (top_threats if isinstance(top_threats, list) else [])
        if isinstance(identifier, str)
    )
    findings = threat_model.findings(path, top_threats=ranked)
    if findings:
        raise SubmissionError(f"{path.name}: " + "; ".join(findings))


def validate_changed_paths(paths: list[str]) -> None:
    """Reject changed paths outside this Task's student-editable surfaces."""
    normalized = {PurePosixPath(path.replace("\\", "/")).as_posix() for path in paths}
    protected = sorted(
        path for path in normalized - ALLOWED_PATHS if not path.startswith(ALLOWED_PREFIXES)
    )
    if protected:
        raise SubmissionError(f"protected path changed: {', '.join(protected)}")


def _changed_paths(root: Path) -> list[str]:
    """Return changes since the commit this checkout branched from."""
    try:
        repository_root = Path(
            subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        ).resolve()
        if root.resolve() != repository_root:
            # The authoring snapshot is nested. Only a generated repository's
            # own history defines student changes.
            return []
        baseline = _baseline_commit(repository_root)
        result = subprocess.run(
            ["git", "diff", "--name-only", baseline],
            cwd=repository_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError("Git history is unavailable for protected-path validation") from exc
    return [line for line in result.stdout.splitlines() if line]


def _baseline_commit(repository_root: Path) -> str:
    """Return the commit a student's changes are measured against.

    Student work happens ahead of `main` - on a branch, or as uncommitted
    edits - and `main` itself keeps moving as this repository receives
    updates after a student has already forked from it. The protected
    boundary is therefore the commit a student actually started from
    (their merge-base with `main`), not the repository's very first
    commit, which a later update may have moved past.
    """
    for candidate in ("origin/main", "main"):
        probe = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", candidate],
            cwd=repository_root,
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            merge_base = subprocess.run(
                ["git", "merge-base", "HEAD", candidate],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            )
            return merge_base.stdout.strip()
    # No `main` branch is reachable - fall back to the repository's single
    # root commit.
    roots = subprocess.run(
        ["git", "rev-list", "--max-parents=0", "HEAD"],
        cwd=repository_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if len(roots) != 1:
        raise RuntimeError("repository must have exactly one protected root commit")
    return roots[0]


def _load_one_document(path: Path) -> dict[str, Any]:
    """Load exactly one plain JSON-compatible YAML mapping.

    A file that is not UTF-8 is reported the same way as one that is not the
    restricted YAML profile: as a public verification failure, not a traceback.
    """
    try:
        documents = list(
            yaml.load_all(path.read_text(encoding="utf-8"), Loader=_RestrictedYamlLoader)
        )
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise SubmissionError(f"{path.name} must contain UTF-8 restricted YAML") from exc
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise SubmissionError(f"{path.name} must contain exactly one YAML mapping")
    return documents[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the Task 4.1 submission.")
    parser.add_argument(
        "--format-only",
        action="store_true",
        help="check the answer sheet's format only (what `poe answers` runs)",
    )
    arguments = parser.parse_args()
    raise SystemExit(main(format_only=arguments.format_only))
