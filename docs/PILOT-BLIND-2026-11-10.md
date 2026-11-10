# SOC blind dry pilot — 10 November 2026

## Method

- Three independent reviewers, one per case. Each received only the participant
  package (extracted outside the builder repository) and the student card. They
  were told not to read instructor-private, holdout labels, or reference rules.
- **Agent-assisted dry pilot**, not a human student pilot. Reviewers wrote their
  own rules, evaluated on training data, tuned, and froze a final rule. Holdout
  was not evaluated.
- Environment: Windows 11, 7.8 GB RAM, PHP 8.2.4.

## Results

| Case | Wall clock | Rule versions | Final TP/FP/FN/TN | Difficulty |
| --- | ---: | ---: | --- | ---: |
| SOC-1 API takeover | 4 m 33 s | 3 | 10 / 0 / 11 / 28 | 2 detection, 3 defensible |
| SOC-2 endpoint | 6 m 44 s | 5 | 4 / 0 / 1 / 19 | 3 |
| SOC-3 DNS beacon | ~7 evaluations | 7 | 12 / 0 / 2 / 12 | 3 |

Naive baselines showed the intended false-positive pressure: SOC-1 naive
7/0/14/28, SOC-2 process-name-only 2/3/3/16, SOC-3 trust-all-IDS 2/2/12/10.

## Defects found and fixed

| # | Finding | Fix |
| --- | --- | --- |
| 1 | `note` contained ground-truth narration; `note contains "Sequential read"` scored TP=12/FP=0 | All generators now replace `note` with a neutral record description |
| 2 | Attacker `device_id="dev-unknown-1"` and `geo="VPN exit"` leaked novelty | Changed to plausible device ids and normal cities; IP remains shared with a benign user |
| 3 | SOC-1 victim had no baseline events | Added benign baseline login/session/reads for the victim in train and holdout |
| 4 | Benign retry lacked `session.created` | Added session events for the retry lookalike |
| 5 | SOC-2 benign explorer event sat inside the malicious sequence | Removed it from the sequence; added a benign Office event so the document stage has an FP cost |
| 6 | No label for "suspicious but unconfirmed" | Added `label_semantics`: benign means not part of a confirmed chain, not "safe" |
| 7 | SOC-3 second IDS alert pointed to `F-BEACON-4` but its time matched cycle 3 | Corrected to `F-BEACON-3` |
| 8 | Rule format undocumented in SOC-2/SOC-3 cards | Added format and engine-limitation sections; documented single-event-per-stage and no interval arithmetic |
| 9 | Participant docs used `data/train/...` while the package is flat | Corrected to `train/...` and `holdout/...` |
| 10 | `freeze` wrote into `instructor-private/` inside the student package | Default output is now `freeze.json` at the package root (gitignored) |

## Calibration

- **SOC-1** is conceptually easiest to start (failure burst is visible) but hard
  to make defensible; the reference rule and the pilot both leave false negatives
  because the engine matches one event per stage.
- **SOC-2** is the hardest (5 rule versions) because the helpdesk/deployment
  context and the orphan process require judgment beyond process names.
- **SOC-3** is medium; periodicity is visible but the benign updater and the
  orphan alert force context.
- Spread 2–3 is acceptable. Keep the case-specific Q8–Q10 wording; do not add
  more engine features just to raise scores.

## Engine limits to state in teaching

- One event per stage; no OR; `group_by` is one field; no interval arithmetic;
  no cross-stage field equality.
- Event-level rules are allowed and often score better than naive sequences.
- Sequence coverage is reported separately from event TP/FP/FN.

## Resource measurements

| Case | Viewer start | Validate | RSS | Private | Dataset |
| --- | ---: | ---: | ---: | ---: | ---: |
| SOC-1 | 0.64 s | 0.06 s | 20.1 MB | 9.2 MB | 33.5 KB |
| SOC-2 | 0.54 s | 0.07 s | 20.2 MB | 9.2 MB | 22.3 KB |
| SOC-3 | 0.54 s | 0.07 s | 20.1 MB | 9.2 MB | 23.8 KB |

## Limits

- Agent reviewers may overperform human students on rule authoring.
- No human pilot yet; difficulty ratings are indicative.
- Holdout scoring was not performed in the pilot.
