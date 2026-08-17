---
name: baseline-comparison
description: Implements a golden-baseline confirmation and drift-detection workflow for network devices — establishes a baseline on first run, compares later snapshots against it, and classifies each result as match or drift for downstream alerting or remediation. Use when building a config-compliance tool, drift monitor, OOB polling loop, or auto-remediation pipeline for network devices.
---

# Baseline Comparison Workflow

## Role & Purpose
Decide, on every polling cycle, whether a device's current config matches
its confirmed "golden" baseline — and what should happen next. This is a
policy/workflow layer on top of the `network-config-diff` skill, which does
the actual field-level comparison.

## State Machine
For each monitored device:

1. **No baseline exists yet**
   - Do not compare anything yet.
   - Pause and prompt an admin to confirm the current snapshot as the
     baseline (store it, e.g. in a `baseline_configs` table/db keyed by
     device ID).
   - Never silently adopt the first snapshot as baseline without
     confirmation — a device polled for the first time mid-incident would
     bake the bad state in as "correct".

2. **Baseline exists**
   - Take a new snapshot, run it through `network-config-diff` against the
     stored baseline.
   - **No diff** → status `match`, nothing to do.
   - **Diff found** → status `drift`. Surface an alert containing the
     structured diff (see `network-config-diff` output format), and wait
     for an explicit decision:
     - **Accept as new baseline** — the change was intentional; overwrite
       the stored baseline with the new snapshot.
     - **Flag for remediation** — the change was unauthorized; hand the
       diff to whatever remediation/auto-fix logic the project uses.
       This skill only classifies and alerts — it does not decide *how*
       to remediate.

## Hard Rule: Detection and Action Are Separate
This skill's job stops at classification (`match` / `drift`) and producing
the diff + alert. It must never itself push config changes to a device.
Any auto-revert or auto-remediation is a distinct, explicitly-authorized
feature with its own approval/audit path — don't fold write-access into
the comparison logic, even if the project's ultimate goal is
auto-remediation.

## Storage Shape (reference)
A simple two-table shape works for most cases:
- `baseline_configs`: one confirmed baseline per device (device_id,
  parsed_config_json, confirmed_at, confirmed_by).
- `snapshots`: every poll result (device_id, parsed_config_json,
  polled_at, diff_result_json, status).

Keep the raw parsed structured config, not just the diff, in both tables —
you need the full baseline to diff against next time, and full snapshots
are useful for audit trails later.

## Logging & Alerting
- Every `drift` classification should produce an audit log entry (device,
  timestamp, diff summary, decision made, who made it) — this is what a
  compliance/audit trail is built from, and what an auto-remediation
  system would replay to prove what happened.
- Alerting channel (Telegram, email, etc.) is out of scope for this skill;
  just ensure the alert payload includes the structured diff so the
  notification can be genuinely informative rather than "something
  changed on device X".

## Related Skills
- `network-config-diff` — does the actual comparison; this skill wraps it
  with baseline state and decision policy.
- `textfsm-parser` — parses raw CLI output into the structured form both
  of the above skills expect.
