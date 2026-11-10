# Feature Specification: SOC Replay and Evaluation Harness

**Feature Branch**: `main` (planning baseline)  
**Created**: 2026-10-26  
**Status**: Ready for planning  
**Input**: Three SOC cases need comparable local replay, rule testing, package separation, and reproducible evaluation.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Student explores assigned events (Priority: P1)

A student opens the assigned case, reads the field dictionary, filters raw events, and follows an event ID back to its unchanged source record. The normal workflow needs no full SIEM or network access.

**Why this priority**: Q1–Q4 and defensible triage require inspectable raw evidence.

**Independent Test**: Load each case in a fresh environment, filter by identity/host/time, and resolve three displayed events to original records.

**Acceptance Scenarios**:

1. **Given** a case package, **when** it is opened, **then** schema version, source zones, record count, checksums, and field descriptions are visible.
2. **Given** a filtered result, **when** an event ID is selected, **then** the original raw event and source timestamp are recoverable without changing its bytes.

### User Story 2 - Analyst tests a candidate rule (Priority: P1)

A student submits a documented rule or query, sees matched event/sequence IDs, and compares those matches with labeled training cases, including normal counterexamples.

**Why this priority**: Q5–Q10 assess reasoning and tuning, not alert volume.

**Independent Test**: Evaluate a fixture rule whose TP/FP/FN/TN counts are known and verify counts plus supporting event IDs.

**Acceptance Scenarios**:

1. **Given** a valid query, **when** training evaluation runs, **then** matched IDs and reproducible confusion-matrix counts are returned.
2. **Given** an unsupported field or invalid time window, **when** evaluation runs, **then** a specific validation error identifies the issue and no partial score is shown.

### User Story 3 - Instructor packages and scores holdout (Priority: P1)

An instructor builds one package per group, freezes a submitted rule, and scores it on private holdout labels. Students receive aggregate feedback only after the scoring gate.

**Why this priority**: Assignment separation and holdout integrity are essential for fair grading.

**Independent Test**: Build all packages, inspect their manifests, freeze a rule by digest, score it twice, and compare identical results without private files in student output.

**Acceptance Scenarios**:

1. **Given** SOC-2 package generation, **when** contents are inspected, **then** no SOC-1/SOC-3 data, private labels, reference rule, or answer key appears.
2. **Given** a frozen rule digest, **when** holdout is evaluated twice, **then** metrics and matched IDs are identical, and the output records rule/dataset versions.

### Edge Cases

- Duplicate or missing event IDs, missing UTC offset, malformed JSON, unknown field, out-of-order timestamps, or a label referring to a nonexistent event.
- A query overmatches almost all normal events; metrics must remain mathematically valid and expose false positives.
- A student machine cannot load the dataset within pilot limits; mentor-hosted fallback must accept the same query contract.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Validate schema, unique event IDs, timestamp/zone, source, and checksums before replay or scoring.
- **FR-002**: Offer an inspectable local search/query interface and preserve raw event references.
- **FR-003**: Support temporal correlation by identity/host and bounded windows; where Sigma is used, document exactly how it maps to the evaluation query.
- **FR-004**: Calculate TP, FP, FN, TN and derived rates from a documented unit of evaluation (event or correlated case), consistently across training and holdout.
- **FR-005**: Keep training labels and holdout labels in separate paths; only training labels may enter student packages.
- **FR-006**: Freeze submitted candidate rules and record hashes of rule, dataset, schema, and evaluator for holdout scoring.
- **FR-007**: Generate three separate student packages plus instructor-only keys/reports; package inspection must fail on leaked private files.
- **FR-008**: Include offline start, query, reset, troubleshooting, and fallback instructions without requiring a live SIEM.
- **FR-009**: Generate or validate datasets reproducibly from recorded seed and tool versions.

### Key Entities

- **Event**: stable ID, case ID, source, original timestamp and zone, normalized UTC timestamp, typed fields, raw record.
- **Sequence label**: case/sequence ID, member event IDs, ground-truth class, analyst explanation; private for holdout.
- **Detection candidate**: rule/query body, schema version, author, frozen digest.
- **Evaluation report**: rule/dataset versions, matched IDs, confusion matrix, validation errors, aggregate feedback.
- **Package manifest**: case ID, allowed files, hashes, sizes, version, distribution record.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of released event IDs and labels pass referential-integrity and time-zone validation.
- **SC-002**: Two runs with identical seed, inputs, and rule produce byte-identical normalized event manifests and equal scores.
- **SC-003**: All three packages contain exactly one assigned case and zero instructor-only files.
- **SC-004**: A reviewer can reproduce every reported TP/FP/FN/TN count from the corresponding event/sequence IDs.
- **SC-005**: On representative 8 GB devices, the full Q1–Q10 workflow works without a full SIEM; record actual memory, load, and query times before setting release limits.

## Assumptions

- One of three SOC groups receives each case. Training labels are visible; holdout truth is private.
- Static replay is sufficient for learning outcomes. No active response or external traffic is part of this feature.
- Dataset size target is below 1 GB per case, subject to pilot measurements.
