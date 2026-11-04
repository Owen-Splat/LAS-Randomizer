# Standalone pickup and GUI changes — draft

These changes target LAS Randomizer 0.41, upstream commit
`9ca45b80728172fa1dd905dac0f28074498aaeae`.

The Seashells, Trendy Game and Shop controls are clickable. Their values persist
through saved settings and the new `LAS2:` settings strings, feed the shuffler,
and select the corresponding mod generators. They default off while the
standalone implementation awaits gameplay validation. Unselected categories
retain vanilla placements. Old unversioned settings strings are rejected rather
than decoded using a different check order; recreate them in this GUI.

## What changes

- Shells: 33 original shell sources, including buried, hidden, bomb-hole and
  underwater sources; five underwater heart-piece sources use the same adapter.
  Source collection flags are separate from the inventory of received shells or
  heart pieces. Original world actors remain in place. All 33 indexed shell
  sources select assigned-item graphics through the original NPC component
  constructor. Cloned shell definitions change only the graphics resource names;
  collision, events and resource ownership remain on the original game path.
  Chest, NPC-gift and Trendy shell sources use their existing presentation routes.
  The actual reward uses upstream item-get presentation. Underwater heart-piece
  world visuals are unchanged.
- Trendy: six one-time physical prizes and the existing final reward are
  shuffled. Preserve all original row indexes and nonempty layout vectors;
  disable obsolete layouts through a false flag. Keep repeat prizes, figurines
  and instrument gates. Actual awards use the upstream item-get helper.
- Shop: ten one-time goods in the shovel/bow, chamber-stone and heart-piece
  positions. Shelf models and localized price/choice messages match the assigned
  goods. Consumables remain repeatable. A stolen dummy queues a persistent
  pending flag; PlayerStart grants the real item once and clears the pending flag.

## Requirements and support

Use a fresh save. Shells and Shop require the clean LAS **1.0.0** `exefs/main`
next to the selected `romfs` folder. The GUI rejects missing or mismatched input
before shuffling. The builder checks the entire executable hash and original
hook instructions. Only 1.0.0 is supported by this native adapter; do not enable
the 1.0.1 update when testing it. Existing original randomizer patches are
generated as usual. No original game files or generated binaries are provided.

Install the updated requirements. The native module is built locally with
Zig 0.14.1 and contains inventory-add/ownership and shell NPC-name selection hooks.
Optional native tests
also require `unicorn==2.1.4`.

Run source tests with `python -m unittest discover -s tests -v`. Asset/native
tests skip unless `LAS_TEST_MOD` points to a privately generated mod folder.
Generate one with `python tests/generate_smoke_mod.py --romfs PATH --output NEW_PATH`.
Set `LAS_TEST_MOD` to the printed mod folder and rerun the tests. The console
layout is also supported by the test generator's `--platform console` argument.

## Validation and remaining work

The complete generator has been exercised with a real 344-location standalone
seed. Tests cover GUI settings, check selection, generated flags/events/models,
localized shop labels and compiled ARM64 inventory interception. Native tests
stub the original inventory functions and selected kernel services.

Validation on 2026-11-04: a new real 344-location seed generated successfully;
all 15 GUI, generated-asset and compiled ARM64 tests passed without skips.
All 33 indexed shell visuals were emitted without stock fallbacks. Constructor
boundary tests verify selection, argument forwarding, unchanged owner state and
identity guards, including overlapping heart-piece indices. They do not execute
the game's renderer or prove scene-entry/resource lifetime safety.