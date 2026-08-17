---
name: network-config-diff
description: Compares two network device configuration snapshots (raw CLI text or TextFSM-parsed structured data) and produces a structured, section-aware diff of added/removed/changed items. Use when the user asks to diff configs, compare running-config vs startup-config, compare two time-stamped snapshots, or needs the core comparison logic behind a config-drift/compliance tool.
---

# Network Config Diff

## Role & Purpose
Produce a reliable, structured diff between two versions of a network device
configuration — reliable enough to drive alerting or auto-remediation
decisions downstream, not just a human-readable text diff.

## Why Not Plain `diff`/`difflib`
Raw line-by-line diffing of CLI config text is noisy and unreliable for
network configs because:
- Line order within a block can vary (e.g. ACL entries, interface list)
  without being a real change.
- Volatile/non-semantic fields exist (timestamps, uptime counters, "! Last
  configuration change at ...", sequence numbers auto-renumbered by the
  device) and must be excluded before comparing.
- The same logical object (an interface, a VLAN, a BGP neighbor) can span
  multiple lines — comparison should be per-object, not per-line.

## Recommended Pipeline
1. **Normalize** both snapshots first:
   - Strip comment/banner lines and volatile fields (timestamps, uptime,
     packet/byte counters, "! Last configuration change...").
   - Normalize whitespace and case where the vendor CLI is case-insensitive.
2. **Parse into structured sections**, ideally with TextFSM templates (see
   the `textfsm-parser` skill) so each config becomes a dict/list keyed by
   logical object: `interfaces`, `vlans`, `acls`, `bgp_neighbors`, etc.
   - If no template exists yet for a section, fall back to grouping raw
     lines by their top-level block (e.g. everything under
     `interface GigabitEthernet0/1` until the next top-level line).
3. **Diff per section**, not the whole file at once:
   - Build a dict keyed by the object's identity (interface name, VLAN ID,
     ACL name+seq, neighbor IP) for both snapshots.
   - Classify each key as `added` (in new, not old), `removed` (in old, not
     new), or `changed` (present in both, field-level values differ).
   - For `changed`, report only the fields that actually differ, with
     old/new values — not the whole object.
4. **Emit a structured result**, e.g.:
   ```json
   {
     "section": "interfaces",
     "identity": "GigabitEthernet0/1",
     "change_type": "changed",
     "fields": {
       "ip_address": {"old": "10.0.0.1", "new": "10.0.0.2"},
       "status": {"old": "up", "new": "administratively down"}
     }
   }
   ```
   A flat list of these records is the diff — easy to filter, count, or
   feed into an alerting/remediation policy.

## Edge Cases
- Missing section in one snapshot entirely (e.g. no BGP config yet) →
  treat every object in that section as `added` or `removed`, not an error.
- Renamed objects (e.g. interface renumbered) will show as one `removed` +
  one `added` unless the caller supplies an explicit identity-mapping rule;
  don't try to guess renames implicitly.
- Always diff on parsed/structured values, never on the raw text of a
  multi-line block, or reordering will produce false positives.

## Output Rules
- Return the diff as a list of structured records (see format above), not
  a text-based unified diff, so it can be consumed programmatically by
  alerting/remediation logic.
- Include a short human-readable summary line per record for logs/alerts,
  but keep the structured fields as the source of truth.

## Related Skills
- `textfsm-parser` — use it to turn raw CLI output into the structured
  data this skill diffs.
- `baseline-comparison` — builds on this skill to decide what to *do*
  when a diff is found (accept as new baseline vs. flag for remediation).
