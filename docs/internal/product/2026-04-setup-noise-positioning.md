# Product Notes: Setup, Noise Reduction, and Positioning

Date: 2026-04-03
Status: working notes

## 1) Setup UX: day-0 ready

Goal: after `innerwarden setup`, a basic user should be operational without extra commands.

Principles:
- Basic path with very few decisions.
- Clear review before apply.
- Agent connection inside setup.
- Ready/fix checklist at the end.

## 2) Noise reduction ideas (high priority)

1. Confidence gate per severity
- Composite score (detector confidence + context + correlation).
- Notify only above threshold for each channel.

2. Notification budget
- Limit alerts per time window.
- Aggregate repeated incidents into compact summaries.

3. Intelligent dedup
- Fingerprint by `detector + entity + tactic`.
- Collapse repeats and show counts/timeline instead of repeated spam.

4. Role-aware baselines
- Different baseline profiles by host role (web, db, bastion, worker).
- Reduce structural false positives.

5. Feedback loop to policy
- Convert repeated false-positive reports into suggested allowlist/suppression rules.
- Keep approval explicit before permanent change.

## 3) Positioning ideas (core message)

Main positioning:
- InnerWarden is active host defense, not just alerting.

Single-line value proposition:
- Detect, contain, and recover in one flow.

Proof points to surface in product:
- Mean time to detect/contain.
- False-positive rate trend.
- Auto-contained incidents ratio.

Packaging:
- Core: visibility + essential protection.
- Enterprise: active defense mode (contain + deceive + recovery).
