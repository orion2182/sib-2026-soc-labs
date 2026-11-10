# Feature Specification: SOC-1 API Account Takeover

**Feature Branch**: `main` (planning baseline)  
**Created**: 2026-10-26  
**Status**: Ready for planning  
**Input**: A distinct API authentication and audit-log case for one SOC group.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Correlate an account sequence (Priority: P1)

The analyst traces unusual sign-in, session changes, and object access in synthetic API logs, and states which chain merits escalation.

**Why this priority**: Q8–Q9 require a behavior sequence, not a count of failed logins.

**Independent Test**: From unlabeled event IDs, a reviewer can reconstruct one supported suspicious chain and distinguish it from unrelated failed logins.

**Acceptance Scenarios**:

1. **Given** the training set, **when** login and API events are correlated by account/session/time, **then** the intended chain is visible with raw IDs and source timestamps.
2. **Given** isolated login failures, **when** the same rule runs, **then** they do not automatically become confirmed takeovers.

### User Story 2 - Reject plausible normal activity (Priority: P1)

The analyst tunes a rule against legitimate travel, retries, and scheduled administrator changes, explaining remaining uncertainty.

**Why this priority**: Q10 and metrics require realistic false-positive pressure.

**Independent Test**: A naive rule triggers on at least one normal sequence, while a context-aware rule can reduce that noise without erasing all suspicious cases.

**Acceptance Scenarios**:

1. **Given** a legitimate travel sequence, **when** examined with session and object context, **then** its classification can be justified as normal or unresolved, not labeled solely by geography.

### Edge Cases

- Clock skew between auth and API services; expired sessions; NAT/shared IP; incomplete session ID; repeated admin maintenance.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Supply synthetic auth, session/audit, and API access events with stable account/session/object references and documented clock offsets.
- **FR-002**: Include a baseline of normal account behavior plus legitimate travel, retry, and scheduled-admin counterexamples.
- **FR-003**: Provide labeled training sequences, private holdout sequences, and instructor explanations keyed to event IDs.
- **FR-004**: Ensure a candidate can answer Q8 (which login starts the chain), Q9 (which API access strengthens it), and Q10 (which similar travel is legitimate) from available evidence.
- **FR-005**: Provide a student card with Q1–Q12, schema, scope, severity guide, and submission format; exclude case truth and holdout labels.
- **FR-006**: Record a reference query and its known training/holdout outcomes for mentor review, without requiring a particular implementation strategy from students.

### Key Entities

- **Account/session**: synthetic identity and session linkage.
- **Auth event**: decision, source context, time, event ID.
- **API access event**: endpoint class, object ID, outcome, session reference.
- **Incident sequence**: linked records, label, explanation, severity recommendation.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A blind reviewer can cite raw IDs for Q8–Q10 and at least one defensible alternative interpretation.
- **SC-002**: Training and holdout each contain suspicious and legitimate account sequences; labels and references validate with the shared harness.
- **SC-003**: The reference query produces inspectable TP, FP, and FN examples or explicitly documented zero-count cases, without relying on a single IP/IOC.

## Assumptions

- The scenario is wholly synthetic; no real credential or API endpoint exists.
- The student recommends containment and handoff; the lab does not require acting on an account.
