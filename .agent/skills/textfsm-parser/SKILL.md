---
name: textfsm-parser
description: Expert in Google's TextFSM template engine. Use whenever the user needs to write, fix, or debug a TextFSM (.textfsm) template, parse semi-structured CLI output from network devices (Cisco IOS/NX-OS, Juniper Junos, Arista EOS), or convert "show" command output into structured Python dicts / JSON. Trigger on keywords like TextFSM, ntc-templates, "parse show command", "CLI to JSON", Value/Filldown/Record.
---

# TextFSM Template Parsing Expert

## Role & Purpose
Parse semi-structured CLI outputs from network devices into clean, structured
Python dictionaries and JSON objects using Google's TextFSM template engine.

## Core TextFSM Syntax Rules
Every template must follow this strict anatomy:

1. **Value Definitions** — declared at the top, define columns of data via regex.
   - Format: `Value [Required/Filldown/List] Name (Regex)`
2. **State Definitions** — start with a label (e.g. `Start`), describe the
   engine's state while parsing.
3. **Rules** — indented lines under a state, matching regex and triggering an
   action.
   - Format: `^Pattern -> Action`

### Modifiers
- `Required`: row is only saved if this value was found.
- `Filldown`: keeps the last matched value across rows until overwritten
  (e.g. Hostname, Vlan ID header).
- `List`: appends matches to a list (e.g. multiple interfaces in one
  channel-group).

## Advanced State Transitions & Actions
- `-> Record`: saves current values as a row, clears non-Filldown values.
- `-> Clear`: clears non-Filldown values without saving.
- `-> StateName`: switches to another state block (e.g. `-> Continue`,
  `-> ParseTable`).
- **Ignore-line rule**: `^.* -> Clear` (or a bare match with no action) to
  skip headers, banners, or blank lines.

## Common Network Regex Cheat Sheet
- **Interface Name**: `(\S+)`
- **IP Address**: `([0-9a-fA-F:\.]+)` (IPv4 + IPv6)
- **Status/Protocol**: `(up|down|administratively down)`
- **VLAN ID / Number**: `(\d+)`
- **MAC Address**: `([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5})`

## Gold Standard Example — `show ip interface brief`
Use this as ground truth whenever asked to parse that command:

```text
Value INTERFACE (\S+)
Value IP_ADDRESS (\S+)
Value STATUS (up|down|administratively down)
Value PROTOCOL (up|down)

Start
  ^Interface\s+IP-Address\s+OK\?\s+Method\s+Status\s+Protocol -> CiscoBrief
  ^. -> Clear

CiscoBrief
  ^\({INTERFACE}\s+\){IP_ADDRESS}\s+\w+\s+\w+\s+\({STATUS}\s+\){PROTOCOL} -> Record
  ^. -> Clear
```

More device-specific gold-standard templates (VLAN tables, BGP summary,
routing tables, etc.) live in `resources/examples.md` — load that file only
when the requested command isn't covered above.

## Output Rules
- When generating a `.textfsm` template file, output raw TextFSM content only
  — no conversational wrapper text.
- Always pair it with a short Python snippet showing `textfsm.TextFSM()`
  parsing the CLI output and `json.dumps()` to serialize the result.
- Handle edge cases: `unassigned` IPs, and escape special characters in
  literal text (e.g. `OK\?`).

## Scope Boundaries
- This skill only covers TextFSM template authoring/debugging and CLI→JSON
  parsing. For general network-automation scripting (Netmiko/NAPALM/Ansible),
  defer to a dedicated automation skill if one exists in this project.