# Archipelago slop-check cleanup

Reviewed on 2026-11-04 using local slop-check 1.1.0.

Before: score 10/100, grade B, 508 findings.
After: score 6/100, grade A, 493 findings.
No scanner suppression directives or scoring changes were added.

## Changes

- Both bundled settings managers now use direct widget access when loading
  saved values. Expected invalid-value/widget errors produce a warning naming
  the setting. Other settings continue loading; unexpected exceptions propagate.
- Four miscellaneous pickup adapters now share their common reward and model
  setup. Each keeps its own actor index, actor type, collection flag, event entry
  point and rotation behavior. The Dream Shrine retains its Yoshi actor type;
  the Lens retains its rotation reset. No shell native hooks were changed.
- Removed inactive Point/Rail experiments and commented-out shop flag calls.
  Active room packing and flag allocation code remain unchanged.
- Source validation accepts the original upstream files or the exact reviewed
  cleanup hashes for four files. Other source fingerprints remain strict. The
  upstream catalog identity remains unchanged for existing seeds.
- Current tests use the bundled source rather than a developer-only sibling path.
- Rebuilt las_switch.apworld and refreshed the package file manifest.

## Validation

All 29 current package tests passed: cleanup regressions, native plans, patch
pipeline and v2 core. The pickup test covers both source copies, four locations,
three item types and ordinary/custom model settings (48 combinations). It checks
event calls, actor identity, flags, model parameters, scale and rotation. These
are adapter-level tests, not renderer or gameplay tests. Settings tests verify
that an invalid value is reported while another setting still loads. Source-pin
tests reject unapproved edits to an approved-cleanup file.

The first unrestricted full discovery exposed an existing legacy test module,
test_prototype.py, which imports the absent las_ap package and old catalog data.
It was left intact and was not included in the 29-test current suite. A full
discovery still requires restoring that legacy test environment or migrating
those tests; this report does not claim every historical suite passes.

## Remaining scanner findings

- 489 happy-path-only findings: calls in the two bundled mod generators. Their
  generation entry points already catch exceptions, emit a traceback/error
  signal and complete the worker lifecycle. Adding a catch at each read/write
  would duplicate handling or risk hiding an error. The pipeline's failure tests
  cover refusing partial publication. These scanner warnings were left visible.
- Four hardcoded-config findings: 127.0.0.1 in the client bridge, runtime config,
  mock game and native diagnostic server. Loopback is intentional for local
  communication. Making these public listener addresses would change behavior.

The scan excludes tests, docs and generated/vendor code by its own rules and
does not inspect the native C/assembly. Grade A is not gameplay certification.
No gameplay, network protocol or release-capability flags were changed.
Nothing was staged, committed or pushed.
