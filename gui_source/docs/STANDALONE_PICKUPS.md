# Standalone pickup and GUI changes — draft

These changes target LAS Randomizer 0.41, upstream commit
`9ca45b80728172fa1dd905dac0f28074498aaeae`. They do not use Archipelago,
an AP client, a server, a `.lasap` file or AP receipt state.

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
  heart pieces. Original world actors remain in place. Ground models remain
  vanilla; the actual reward uses upstream item-get presentation.
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
Zig 0.14.1 and contains only inventory-add/ownership hooks. It has no networking,
frame polling, actor rendering hooks or AP save format. Optional native tests
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

This standalone port has **not been played in Ryujinx or on hardware yet**.
Earlier gameplay confirmations apply to the AP implementation, not this port.
Keep the PRs in draft until purchases, stealing, traps, save/reload, all featured
Trendy prizes/final reward, shell source revisits and diving pass in a fresh
standalone save. Frozen executable packaging of Zig and native source resources
also needs a build test; source-based generation is what has been verified.

The known shell ground-model mismatch remains intentionally unresolved. Do not
reintroduce the failed global shell/heart-piece NPC graphics replacements: they
caused room-transition crashes in the earlier development build.
