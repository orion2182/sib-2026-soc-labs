# SOC Labs 2026 Constitution

## Core Principles

### I. Three distinct detection problems

SOC-1, SOC-2, and SOC-3 MUST have different operational narratives, event sources, detection hypotheses, normal-noise examples, and required analyst decisions. Shared code MAY cover schema validation, replay, query evaluation, metrics, and package generation. Shared fixtures MUST NOT make the three cases equivalent with renamed fields.

### II. Evidence and labels are reproducible

Every event MUST have a stable ID, source, timestamp with zone or UTC offset, and schema version. Generation MUST record seed and input versions. Each training label and private holdout label MUST identify the specific event or correlated sequence that justifies it. Reviewers MUST be able to recompute counts, confusion matrices, and example triage from raw events. The final scoring run MUST use a frozen candidate rule and must not disclose private labels to students.

### III. Detection includes normal behavior and uncertainty

Each case MUST include legitimate activity that resembles the suspicious pattern. Student work MUST cover baseline, hypothesis, rule/query, validation, tuning, triage, severity, escalation, and limits. A static IOC match alone MUST NOT earn full credit. The reference rule is not a guaranteed universal detector; the answer key MUST document false positives, false negatives, and telemetry gaps.

### IV. Safe, separate distribution

All identities, hosts, domains, addresses, and records MUST be synthetic. Documentation-only addresses and reserved domains SHOULD be used. No lab step may require scanning external systems, active malware, callbacks, or live campus telemetry. Each group MUST receive only its assigned case. Reference rules, holdout labels, scenario truth, and pilot observations MUST remain instructor-only and outside this public repository.

### V. Lightweight, inspectable operation

The required student workflow MUST run on static datasets and a lightweight local viewer/query tool or equivalent documented method. A full SIEM MUST NOT be required on laptops. Design target is less than 1 GB per case dataset and usability on an 8 GB RAM host; these are release hypotheses, not assurances. A representative-device pilot MUST measure load, query, and scoring time, and trigger a mentor-hosted fallback if needed.

## Learning and Calendar Constraints

The lab follows the fixed SIB calendar from **20 November to 23 December 2026**. Q1–Q12 and the milestones in the research document form the student-facing learning contract. G0–G5 checks may withhold or correct a faulty package but MUST NOT silently change the calendar. Three cases are assigned to three groups. Rules may use Sigma where its event semantics fit; a documented query format is acceptable for temporal correlation that Sigma alone cannot express. ATT&CK Detection Strategies are references for hypotheses, not substitutes for event evidence.

## Delivery Gates

Before implementation, every feature spec MUST define its independent user journey, observable acceptance cases, exclusions, and measurable success. Before release, a reviewer MUST verify schema and labels, training/holdout split, deterministic regeneration, reference rule outcomes, legitimate counterexamples, answerability of Q1–Q12, package separation, and resource results. A blind pilot MUST compare the three cases for effort, ambiguity, and scoring fairness; adjust fixtures rather than inventing metric thresholds in advance.

## Governance

This constitution governs the shared harness and the three case features. Any amendment requires a reason and impact review for specs, student cards, reference rules, labels, and scoring. Use semantic versioning: MAJOR for incompatible changes, MINOR for expanded requirements, PATCH for clarification. The copied research document is source context; this constitution and feature specs are the active build contract.

**Version**: 1.0.0 | **Ratified**: 2026-10-26 | **Last Amended**: 2026-10-26
