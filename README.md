# Coldline Task 4.1 — Threat model

This repository starts from the checkpoint that closed Project 3, extended in one way: each
reading can now carry a free-text handling note, and the worker retrieves the matching procedure
through `Retriever` and sends the reading, the note, and the procedure excerpt to the model
provider. That request is the exception-resolution workflow you model in this Task and secure
across Project 4. The repository also supplies the material for a threat model under
`docs/security/`: the workflow as numbered elements and flows, a catalog of candidate threats,
the scoring rule, and the control matrix.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tripleten-com/ai-system-engineering-curriculum-sprint-4-task-4-1/tree/main)

## Start the system

Prerequisites are Python 3.12 and Docker with Compose v2. The supplied bootstrap supports macOS
arm64/x86-64, Windows x86-64, and Linux x86-64/aarch64, and installs pinned uv 0.11.8 under
`.tools/bin`. If your computer cannot run the stack locally, use the Codespaces button above.

On macOS and most Linux distributions the interpreter is `python3`; substitute it wherever these
commands say `python`.

```shell
python infra/scripts/bootstrap.py
./.tools/bin/uv sync --frozen
./.tools/bin/uv run --frozen poe preflight
./.tools/bin/uv run --frozen poe start
./.tools/bin/uv run --frozen poe ready
./.tools/bin/uv run --frozen poe ingest
```

PowerShell and POSIX wrappers are available under `infra/scripts/`. After uv is on `PATH`, the
shorter `uv run --frozen poe <task>` form works; in PowerShell on Windows the pinned binary is
`.tools/bin/uv.exe`.

| Service | Local URL | Purpose |
|---|---|---|
| API | `http://localhost:8000` | Submit readings, poll exception summaries, search procedures |
| Jaeger | `http://localhost:16686` | Open the trace `poe scenario` prints and match its spans to the workflow elements |
| Grafana | `http://localhost:3000` | Use the focused diagnostics dashboard |
| Prometheus | `http://localhost:9090` | Query bounded metrics and inspect the deployed alert rule |
| Alertmanager | `http://localhost:9093` | Inspect firing and resolved alerts |
| LocalStack S3/SQS | `http://localhost:4566` | Inspect the emulated object-storage and queue endpoint |

Each of these ports can be overridden by setting the matching `COLDLINE_API_HOST_PORT`,
`COLDLINE_JAEGER_HOST_PORT`, `COLDLINE_GRAFANA_HOST_PORT`, `COLDLINE_PROMETHEUS_HOST_PORT`,
`COLDLINE_ALERTMANAGER_HOST_PORT`, or `COLDLINE_LOCALSTACK_HOST_PORT` environment variable in your
shell environment or a local `.env` file (copy `.env.example`) if a default collides with
something already running on your machine. Keep the override in place for every `poe` command;
the Jaeger URL above then uses the port you chose.

This Task runs as its own Compose project, `coldline-task-4-1`. If an earlier Task's stack is
still running, run `poe stop` in that Task's repository first; otherwise `poe start` here fails
because the published ports are already taken.

PostgreSQL, Redis, worker metrics, and OTLP remain inside the Compose network. Codespaces uses the
same `compose.yaml` and keeps every forwarded port private. Redis keeps running only for an
earlier checkpoint's own contract test; no composition root reads it anymore.

## Command path

For this Task, run the supplied commands in this order:

```text
poe start
poe ingest
poe scenario
poe answers
poe verify
```

The exact public command is `./.tools/bin/uv run --frozen poe verify`, run from the repository
root. Where a Task page shortens a command to `poe <task>`, that is the form it means.

| Command | Use |
|---|---|
| `poe scenario` | Send the supplied out-of-range reading, with its handling note, through the running stack; print `exception_id`, `api_trace_id`, `worker_trace_id`, `state`, `scenario_id`, `status_url`, `jaeger_url`, and `grafana_url`. The worker continues the trace the API started, so both trace ids name one trace |
| `poe answers` | The answer sheet's format only: the published shape, known ids, and a control scope keyed by the ranked threats. It judges none of the values |
| `poe threat-model` | The same check in full: the format, the permitted-files boundary (the diff from your merge base touches only the two permitted files), every template marker replaced, and the structure of the threat model's four sections. It judges nothing about what they say |
| `poe threat-model-contract` | One static pytest check per Check-list row over `submission.yaml` and `docs/student/threat-model.md`, so a failure names the row it belongs to |
| `poe verify` | The public student verification path: it starts the stack, exercises the inherited platform, and runs this Task's own checks: the answer format, the permitted-files boundary, the template markers, and the threat model's structure |
| `poe queue-contract`, `poe slo-contract`, `poe gate-contract`, `poe runbook-contract` | Project 3's own checks, inherited and passing as shipped; `poe verify` runs them |
| `poe contract` | Check interfaces, boundaries, submissions, and repository structure |
| `poe smoke` | Check the initialized running platform |
| `poe e2e` | Run the external API-to-worker workflow, including the joined trace |
| `poe student-tests` | Run the supplied tests under `tests/student/`; this Task permits no additions there |
| `poe migrate`, `poe migrate-down`, `poe migrate-current` | Step the schema by hand; the initializer brings it to head on every start |
| `poe restart` | Restart the existing API and worker containers **without rebuilding** |
| `poe stop` | Remove containers and the network, keeping named volumes |
| `poe reset` | Remove containers, the network, and local named volumes |

`poe verify` starts the stack, ingests the supplied corpus, runs the smoke tests, the
end-to-end exception workflow, the inherited queue, SLO, gate, and runbook checks, this Task's
own answer-format, permitted-files, template-marker, and structure checks, and the supplied
student tests. Nothing in it judges which flows, categories, likelihoods, threats, or controls
you chose: the protected answer check does that after you submit on the platform. The
Project 3 exercise commands (`poe inject-failure`, `poe redrive`, `poe trigger-alert-load`,
`poe verify-alert-recovery`, `poe dev-failure-lab`) still run but are not part of this Task.

## Folder map

```text
repository root/
├── docs/                Student guidance, public contracts, fidelity notes, and the security material
│   ├── contracts/       Machine-readable public contracts, including this Task's answer schema
│   ├── fidelity/        Local-runtime boundary notes for each active adapter
│   ├── security/        The supplied workflow description, threat catalog, scoring rule, and control matrix
│   ├── architecture/    Supplied vector engine technical profiles, in prose
│   ├── retrieval/       Supplied retrieval pipeline reference
│   └── student/         This Task's contract, your threat model, and the supplied Project 3 runbook
├── config/              Retrieval configuration, settled and supplied from Sprint 2
├── infra/               Local setup and runtime configuration
│   ├── containers/      The API and worker Dockerfiles, with the build identity arguments
│   ├── observability/   Prometheus, Alertmanager, and Grafana configuration
│   ├── release/         The supplied release manifest, unchanged
│   ├── corpus/          Supplied synthetic corpus, query set, and designated investigation
│   ├── judge/           Supplied cached judge evidence and its provenance record
│   ├── profiles/        Supplied engine and emulator profiles, and their provenance record
│   └── postgres/        Database initialization and the migration baseline stamp
├── loadtest/            Supplied traffic profile and provider-latency harness
├── migrations/          Alembic environment, revision template, and revisions, including the handling-note column
├── src/
│   ├── api/             HTTP application code, the retrieval and document paths, composition
│   ├── worker/          Background application code, the procedure lookup, the dead-letter depth poller
│   ├── domain/          Shared domain code, contracts, the failure taxonomy, service and repository contracts
│   ├── ports/           Application interfaces
│   └── adapters/        Technology-specific implementations, including the model emulator and the SQS adapter
└── tests/
    ├── unit/            Isolated behavior checks
    ├── benchmark/       Supplied evaluation harness, metrics, and adoption policy
    ├── contract/        Interface, retrieval, and repository checks, and this Task's answer and threat-model checks
    ├── diagnostics/     Supplied stage inspector
    ├── doubles/         Supplied deterministic test doubles
    ├── failure/         Supplied Project 3 failure-lab and exercise scripts; not this Task's work
    ├── student/         Supplied student tests; no additions in this Task
    ├── smoke/           Running-platform checks
    └── e2e/             Supplied workflow tools and checks, including `poe scenario`
```

## Overview

Use the Task 1 lesson (Task 4.1 in this repository) to decide what to do. This README covers
local setup and repository orientation.

1. `README.md` — local setup, commands, and permitted changes.
2. [`docs/student/task-4-1-contract.md`](docs/student/task-4-1-contract.md) — what this Task
   assesses and who assesses it, the Check-list rows and the checks that read them, and the
   two permitted paths.
3. [`docs/security/workflow.md`](docs/security/workflow.md) — the request as elements and
   flows, each element's trust group, and where each appears in the trace.
4. [`docs/security/threat-catalog.yaml`](docs/security/threat-catalog.yaml),
   [`docs/security/scoring.md`](docs/security/scoring.md), and
   [`docs/security/control-matrix.md`](docs/security/control-matrix.md) — the threats, the
   rule, and the controls.
5. [`docs/student/threat-model.md`](docs/student/threat-model.md) — the template you complete.

The application source lives in five flat packages:

| Package | Responsibility |
|---|---|
| `api` | HTTP delivery, API use cases, the retrieval workflow, versioned routes, configuration, and composition |
| `worker` | Background processing, retries, procedure lookup, the dead-letter depth poller, configuration, and composition |
| `domain` | Provider-neutral contracts, state rules, identity, redaction, embedding, chunking, fusion, access constraints, failure classification, service and repository contracts |
| `ports` | Exactly five visible application interfaces |
| `adapters` | PostgreSQL, pgvector retrieval, LocalStack SQS/DLQ, S3-compatible object storage, the deterministic model emulator, the resilient model-provider wrapper, logs, traces |

`src/api/bootstrap.py` and `src/worker/bootstrap.py` compose each process from its settings and
adapters. Process settings live in `src/api/config.py` and `src/worker/config.py`.

## The five ports

Find the available interfaces in `src/ports/`. A port describes an application capability; an
adapter provides it using a concrete technology.

| Port | General responsibility |
|---|---|
| `ModelProvider` | Call an AI model service; from this checkpoint it returns the provider's raw answer text |
| `Retriever` | Look up relevant context or documents; from this checkpoint the worker calls it too |
| `ObjectStore` | Store large binary objects or files |
| `JobQueue` | Publish and consume background work |
| `SecretProvider` | Read API keys and credentials; no adapter is composed yet |

## Test levels

| Level | Requires Compose | Main question |
|---|---:|---|
| Unit | No | Does one responsibility behave correctly, including failures? |
| Contract | Some | Do interfaces, schemas, paths, and dependency rules stay compatible? |
| Smoke | Yes | Did the complete local platform initialize and become observable? |
| E2E | Yes | Can an external client complete the supplied workflow, in one trace? |

Contract checks marked `runtime` need the running stack. `poe contract` skips them; `poe verify`,
`poe runtime-contract`, `poe queue-contract`, `poe slo-contract`, and `poe gate-contract` run them.
Contract checks marked `assessed` read your two files and are expected to fail on a fresh
checkout; `poe contract` skips them too, and `poe threat-model-contract` and `poe verify` run them.

## Submission checks

Run `poe verify` locally before opening your student pull request. Public GitHub CI repeats
the student checks, running `poe answers` first so a malformed sheet fails fast. The protected
answer check runs on the platform after you submit: it compares your boundary flows, categories,
likelihoods, ranked threats, and control scope with the reference without showing you the
reference, so a green `poe verify` does not mean it has passed. Follow the Task lesson's
instructor-review and progression policy.

## Task boundary

Task 4.1 asks you to complete the answer sheet and the threat model, run `poe verify`, open a
pull request that changes only those two files, and add the trace id and your five ranked
threats with their controls to the pull request description.

The only student-editable paths are:

- `submission.yaml`
- `docs/student/threat-model.md`

Keep the supplied material under `docs/security/`, the application code, the migrations,
`compose.yaml`, every test file, and `.github/workflows/task.yml` exactly as supplied; the public
check compares the diff from your merge base against these two permitted files and reports any
other change as a boundary violation. Rate every threat against the code as it is now, before
any Project 4 control exists.

### Student walkthrough

See **Task 1: Threat model** in your course platform for the full walkthrough. In outline: start
the stack, run `poe scenario`, open the trace in Jaeger and match its spans to the elements in
`docs/security/workflow.md`, mark the flows that cross a trust boundary, classify and rate each
catalog threat from the code with `docs/security/scoring.md`, rank them, choose a control for each
of the top five from `docs/security/control-matrix.md`, complete `docs/student/threat-model.md`,
run `poe verify`, open and merge your pull request, and submit on the platform.

## Operational limits

This local system does not authenticate users, terminate TLS, or manage production secrets.
The Compose PostgreSQL password and the LocalStack access keys are local-only non-secret
credentials. The worker's model-provider key is a development literal for the emulator; it
grants nothing anywhere. Never place real credentials, personal data, or production records in
this repository. The handling note in the supplied scenario is synthetic; test with the supplied
readings only.

Alertmanager here is configured with a "default" receiver that has no notification integration:
alerts are queryable through its own API but never sent anywhere real. Never add a webhook, email,
Slack, or paid integration; Sprints 1-4 are emulator-only and never call a hosted endpoint.

LocalStack's SQS emulation is a local reliability primitive, not a managed-service durability,
IAM, availability, or cost claim. Stopping and starting one Compose container is a local fault
control, not an ECS service event. See [JobQueue fidelity](docs/fidelity/JobQueue.md) for the
exact boundary.

Named volumes preserve local PostgreSQL, Redis, Prometheus, Alertmanager, Grafana, and Jaeger state
across `poe stop`. LocalStack object and queue contents are deliberately not persisted; the
initializer re-uploads the supplied corpus artifacts and re-provisions the queue on every start.
The `poe reset` command deletes the named volumes. This topology makes no backup, replication,
high-availability, disaster-recovery, capacity, latency-SLO, or availability claim beyond what
Project 3 settled.

See [JobQueue fidelity](docs/fidelity/JobQueue.md),
[ModelProvider fidelity](docs/fidelity/ModelProvider.md),
[ObjectStore fidelity](docs/fidelity/ObjectStore.md), and
[Retriever fidelity](docs/fidelity/Retriever.md) for the active adapter boundaries. The
[local runtime evidence](docs/fidelity/local-runtime.md) records the current measurement and its
qualification limits.
