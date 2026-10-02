# Task 4.1 — Threat model contract

Model one exception-resolution request with STRIDE, rank its threats with the supplied scoring
rule, and select a control for each of the five highest-ranked. You read the supplied material
under `docs/security/`, follow one request's trace, read the code on each threat's path, and
record your answers in `submission.yaml` and your threat model in `docs/student/threat-model.md`.
You write no application code.

## What is assessed, and by whom

| Assessed | By |
|---|---|
| The pull request changes only `submission.yaml` and `docs/student/threat-model.md` | Automated, in this repository |
| `submission.yaml` has the published shape: known flow, threat, and control ids, one category and one likelihood per catalog threat, five ranked threats, one control per ranked threat | Automated, in this repository (`poe answers`, repeated by `poe verify`) |
| `docs/student/threat-model.md` replaces every template marker and carries the entries each section asks for | Automated, in this repository (`poe verify`) |
| Your boundary flows, categories, likelihoods, ranked top five, and control scope | Protected automated check, after you submit on the platform |
| What your boundaries, likelihood bases, abuse cases, and omissions say | Your instructor, at the Task 4 Instructor Review; you use the model again at the Project Defense |

The inherited Project 3 checks (smoke, end-to-end workflow, queue, SLO, gate, and runbook
contracts) also run inside `poe verify`, over the supplied checkpoint, and pass as shipped.
They assess the checkpoint you inherited, not your work here.

## The supplied material

| File | What it holds |
|---|---|
| `docs/security/workflow.md` | The request as numbered elements (E1 to E10) and data flows (DF-01 to DF-13), each element's trust group, who controls it and who writes its data, and where each element appears in the trace |
| `docs/security/threat-catalog.yaml` | Seventeen candidate threats (TH-01 to TH-17), each with its element, its flow where one applies, and a plain-language description |
| `docs/security/scoring.md` | The six STRIDE categories by the property they break, the likelihood rule, the supplied impact per threat, the score rule, and the tie-breaking order |
| `docs/security/control-matrix.md` | Fifteen controls (C-01 to C-15), each with a purpose, an element, the one property it addresses, and where it acts |

None of these is student-editable. The public check compares the diff from your merge base
against the two permitted files and reports any other change as a boundary violation.

## Commands

```shell
poe scenario                # send the supplied reading; print the exception and trace ids
poe answers                 # the answer sheet's format only
poe threat-model            # format, permitted files, template markers, section structure
poe threat-model-contract   # one static pytest check per Check-list row, over your two files
poe verify                  # the full public path
```

Start the stack per `README.md` first; `poe verify` starts it again itself and ingests the
supplied corpus. `poe answers`, `poe threat-model`, and `poe threat-model-contract` are static
and need no stack.

## Check-list rows and the checks that read them

| Check-list row | Check |
|---|---|
| Every id in `answers.boundary_flows` is a flow in `docs/security/workflow.md` | `test_every_boundary_flow_is_a_flow_in_the_workflow` |
| Every threat in the catalog has one STRIDE category in `answers.threat_categories` | `test_every_catalog_threat_has_one_stride_category` |
| Every threat has one likelihood in `answers.likelihood` from the scale | `test_every_catalog_threat_has_one_likelihood_from_the_scale` |
| `answers.top_threats` lists five catalog ids in rank order | `test_top_threats_lists_five_catalog_ids_in_rank_order` (five distinct ids; the order itself is the protected check's question) |
| Each threat in `answers.top_threats` has one control id from the matrix in `answers.control_scope` | `test_each_top_threat_has_one_control_from_the_matrix` |
| `submission.yaml` passes the public answer-format check | `test_submission_passes_the_public_answer_format_check`, and `poe answers` |
| Your boundary flows, categories, likelihoods, top threats, and control scope pass the protected answer check | The protected check on the platform; no check in this repository reads the correct values |
| `docs/student/threat-model.md` replaces every template marker | `test_threat_model_replaces_every_template_marker` |
| The first section names the trace id you followed | `test_first_section_names_the_trace_id_followed` (32 hexadecimal digits) |
| The first section explains what differs in trust across every boundary you marked | Your instructor; no automated check reads the sentences |
| The second section names the file and behavior behind each likelihood | `test_second_section_has_a_line_for_each_catalog_threat` (one line per catalog id; what it says is your instructor's) |
| The third section has an abuse case for each of the five top threats | `test_third_section_has_an_abuse_case_for_each_top_threat` |
| The last section names at least one threat or boundary the model leaves out | `test_last_section_names_what_the_model_leaves_out` (the section is not empty; what it names is your instructor's) |
| The pull request modifies only `submission.yaml` and `docs/student/threat-model.md` | `test_submission_change_stays_within_the_permitted_diff`, and `poe threat-model` inside `poe verify` |

All of these live in `tests/contract/test_threat_model.py` except the last, which is in
`tests/contract/test_authoring_contract.py`. They are marked `assessed`: `poe contract` leaves
them out, and `poe threat-model-contract` and `poe verify` run them. A fresh checkout fails
most of them, which is the exercise.

## What the checks verify

| Check | What it looks at |
|---|---|
| `tests/contract/submission_validation.py` (`poe answers`) | `submission.yaml` is one plain YAML mapping with the published keys; every flow, threat, and control id is one the supplied material names; each category is one of the six STRIDE values and each likelihood one of `low`, `medium`, `high`; `answers.top_threats` holds five distinct ids and `answers.control_scope` is keyed by exactly those five; the sheet is not a copy of `submission-sample.yaml` |
| `tests/contract/submission_validation.py` in full (`poe threat-model`, inside `poe verify`) | The format above, then: the diff from the merge base with `main` touches only the two permitted files, with no directory prefix exempted; no template marker remains in `docs/student/threat-model.md`; and the structural checks below |
| `tests/contract/threat_model.py` | The four headings are present, once each, in order; no template marker remains; the first section holds a trace id; the second has a line for each catalog threat id; the third has an entry for each id in `answers.top_threats`; the last has content |
| `test_submission_change_stays_within_the_permitted_diff` | The same boundary asserted as a pytest case: every changed path is one of the two permitted files |

The four headings, exactly as the template carries them:

```text
## 1. Boundaries and the trace
## 2. Likelihood basis
## 3. Abuse cases
## 4. What this model leaves out
```

## Student-editable paths

- `submission.yaml`
- `docs/student/threat-model.md`

That is the whole list. The supplied material under `docs/security/`, the application code,
the migrations, `compose.yaml`, the tests, and the workflows stay as supplied. Before you push,
run `git status` and `git diff --stat`: if anything else changed, the public check reports the
boundary violation rather than your work.
