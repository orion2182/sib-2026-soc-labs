# Feature Specification: SOC-3 DNS and Network Beacon

**Feature Branch**: `main` (planning baseline)  
**Created**: 2026-10-26  
**Status**: Ready for planning  
**Input**: A distinct DNS/connection/IDS correlation case for one SOC group.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Test a temporal beacon hypothesis (Priority: P1)

The analyst inspects static Zeek-like DNS/connection and Suricata EVE-like records, then explains whether periodic contact plus network context supports a beacon hypothesis.

**Why this priority**: Q8–Q9 require time series and cross-source correlation.

**Independent Test**: A reviewer can reconstruct intervals and link supporting DNS, connection, and IDS records by host/time/flow ID.

**Acceptance Scenarios**:

1. **Given** intended beacon events, **when** intervals and destination patterns are calculated, **then** the pattern is observable from event IDs and times.
2. **Given** an IDS alert without corroborating traffic, **when** triaged, **then** the case remains a hypothesis rather than a confirmed incident.

### User Story 2 - Identify scheduled benign polling (Priority: P1)

The analyst compares suspicious periodicity with software updates and service polling, tuning the rule with host and destination context.

**Why this priority**: Q10 requires a realistic false-positive case.

**Independent Test**: A periodicity-only detector matches a benign case, while a contextual query can distinguish it or state residual ambiguity.

**Acceptance Scenarios**:

1. **Given** approved update polling, **when** its owner, destination class, and schedule are checked, **then** a defensible normal classification is possible.

### Edge Cases

- DNS caching, randomized intervals, missing connections, NAT, clock offset across sensors, truncated capture, and noisy update services.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Supply synthetic DNS, connection, and IDS events with stable host/flow references, sensor IDs, source times, and documented field mapping.
- **FR-002**: Include suspicious and legitimate periodic patterns with enough intervals to test the stated hypothesis; preserve observed jitter instead of a trivial exact-period marker.
- **FR-003**: Provide labeled training sequences, private holdout, a reference query, and instructor explanations linked to raw IDs.
- **FR-004**: Ensure Q8 (time/domain distinction), Q9 (Zeek/Suricata corroboration), and Q10 (normal polling false positive) are answerable.
- **FR-005**: Provide student card, safe documentation-only domains/IPs, schema, and triage template; no real DNS callback or packet replay onto the network.
- **FR-006**: Make the temporal-query representation explicit if Sigma syntax cannot express the complete correlation.

### Key Entities

- **DNS event**: query, response class, host, sensor, timestamp, ID.
- **Connection event**: host, destination, flow/connection ID, timing, volume summary.
- **IDS event**: signature/category and linkable flow/time context.
- **Behavior sequence**: event references, interval summary, label, explanation.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A blind reviewer can answer Q8–Q10 with event IDs and measured intervals.
- **SC-002**: Training and holdout each contain a legitimate periodic lookalike and a case requiring cross-source review.
- **SC-003**: All cross-source linkages and source time offsets validate; a reference query shows reproducible metrics.

## Assumptions

- All events are static synthetic records; no live sensor, PCAP playback, or outbound network traffic is needed.
- An alert may support escalation without proving command-and-control with certainty.
