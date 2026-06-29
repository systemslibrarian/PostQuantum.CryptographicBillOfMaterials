# ADR 0001 — Fail-closed config loading and justified-only waivers

- Status: Accepted
- Date: 2026-06-28

## Context

`cbom.config.json` can raise severity floors, set the CI gate (`failOn`), and waive rules. Two behaviors
undermined the tool's core **fail-closed / misuse-resistance** principles:

1. A config that existed but failed to parse was caught and the scan continued **on built-in defaults**. A
   single typo in a config that raised a floor silently dropped that floor — the finding could fall below
   `--fail-on` and CI (which gates on exit code, not console diagnostics) would go green.
2. Disabling a rule (`"enabled": false`) suppressed its findings **with or without a justification**, so an
   unjustified or rubber-stamped waiver could quietly remove findings from the BOM.

Both let a careless or malicious config produce a misleading "clean" result — the exact outcome the threat
model forbids.

## Decision

1. **A present-but-unparseable config is fatal.** `ConfigLoader` throws `ConfigException`; the CLI reports it
   and exits **3** (usage error). We never scan on defaults when a config exists but cannot be honored. An
   explicitly passed `--config` that does not exist is likewise fatal.
2. **A waiver only suppresses when it is justified and unexpired.** Disabling a rule without a
   `waiverJustification` (or with an expired `waiverExpiry`) **retains** the finding and emits a diagnostic;
   it is never silently dropped. The `audit` profile annotates even justified waivers instead of suppressing.

## Consequences

- Turning off a noisy rule now requires stating *why* — a small friction that buys an auditable trail and
  removes the silent-suppression path. This is intentional.
- Behavior change: configs that previously "worked" by being silently ignored now fail loudly. This is the
  correct fail-closed posture and is covered by integration tests (malformed config → exit 3) and unit tests
  (unjustified/expired waiver → retained).
- Severity floors remain raise-only; all applied config and waivers are recorded in CBOM metadata.
