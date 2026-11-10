# Feature Specification: SOC-2 Suspicious Endpoint Execution

**Feature Branch**: `main` (planning baseline)  
**Created**: 2026-10-26  
**Status**: Ready for planning  
**Input**: A distinct host process and script detection case for one SOC group.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Trace a process chain (Priority: P1)

The analyst uses curated synthetic Windows/Sysmon-style events to follow a parent-child process chain and linked activity, identifying the host/account requiring triage.

**Why this priority**: Q8–Q9 test process context and escalation, not an executable name alone.

**Independent Test**: A reviewer reconstructs an intended sequence with process GUIDs, host, user, and event IDs without ambiguous reuse of PID alone.

**Acceptance Scenarios**:

1. **Given** a suspicious chain, **when** joined by stable process identity and time, **then** parent, child, and follow-on action are traceable.
2. **Given** missing parent telemetry, **when** the chain is assessed, **then** the gap is visible and the conclusion remains bounded.

### User Story 2 - Distinguish helpdesk activity (Priority: P1)

The analyst tunes detection against legitimate helpdesk scripts and IT deployments while preserving a meaningful suspicious chain.

**Why this priority**: Q10 and false-positive analysis require benign lookalikes.

**Independent Test**: A naive process-name match alerts on benign deployment; context fields support a justified distinction.

**Acceptance Scenarios**:

1. **Given** a signed/approved helpdesk script event, **when** contextual metadata is reviewed, **then** it can be marked legitimate without suppressing the suspicious chain by broad allowlisting.

### Edge Cases

- PID reuse, missing process GUID, delayed event arrival, script content truncation, scheduled maintenance, and multiple users on a host.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Provide curated synthetic process, script, and follow-on events with source schema, host/user IDs, process GUIDs, parent GUIDs, and original timestamps.
- **FR-002**: Include host inventory and a maintenance calendar that make normal deployment explanations testable.
- **FR-003**: Supply labeled training sequences, private holdout, event-linked ground truth, and a reference detection query.
- **FR-004**: Ensure Q8 (strong parent-child anomaly), Q9 (host/account escalation), and Q10 (legitimate helpdesk exclusion) have evidence-backed answers.
- **FR-005**: Provide the shared Q1–Q12 student card and a triage template; exclude instructor-only truth and holdout labels.
- **FR-006**: Use inert text/event records only; no executable malware, scripts that run on student machines, or live endpoint collection.

### Key Entities

- **Host/account**: synthetic inventory and ownership context.
- **Process event**: GUID, parent GUID, command-line representation, signer/context, time, event ID.
- **Maintenance record**: approved script/deployment window and host scope.
- **Incident sequence**: event linkage, label, severity, uncertainty.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A blind reviewer can answer Q8–Q10 with raw IDs and one explicit telemetry limitation.
- **SC-002**: Every labeled chain has resolvable event IDs; duplicated PID alone cannot change the expected result.
- **SC-003**: A reference query distinguishes at least one intended suspicious chain from at least one legitimate helpdesk/deployment lookalike.

## Assumptions

- Windows/Sysmon format is represented as inert JSON; students do not need a Windows VM.
- Escalation is a recommendation, not live host isolation.
