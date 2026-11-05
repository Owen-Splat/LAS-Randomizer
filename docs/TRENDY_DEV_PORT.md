# Trendy Game fix for the downloaded dev branch

This package ports only the standalone Trendy Game fix onto the supplied dev
source. It does not include the earlier shell/shop/native port experiment.

## Apply and test

1. Extract your original LAS-Randomizer-dev.zip into a fresh folder.
2. Extract the CONTENTS of dev changed files.zip into that folder, merging
   folders and replacing the listed files. The archive uses repository-relative
   paths; do not create an extra nested source folder.
3. Use dev's normal Python 3.12 environment and requirements.txt.
4. Launch randomizer.py and enable Trendy Game. Its six physical prizes and
   existing final reward can now shuffle. Uncheck it to keep all seven vanilla.
5. Generate into a new output folder and test with a fresh save.

Dev's own exl/main.npdm and exl/subsdk9 runtime files are still required for
generation. They are absent from the original source ZIP and are not part of
this Trendy-only change. Use the upstream dev runtime, available at
https://github.com/Owen-Splat/DEV-BUILD-LASR/tree/d7d76a89f0acf1657df3f2737c1d9780e5a14bef/exl
and place both files in an exl folder alongside randomizer.py.

## Scope

- Enable dev's Trendy Game checkbox.
- Include all seven Trendy locations in settings and allow them into the pool.
- Generate six physical prize models from assigned items. Traps use a green
  rupee model while the reward event still applies the assigned trap.
- Keep native row indexes, nonempty layouts, repeat prizes and figurines.
- Preserve dev's general shield/bomb prize availability fixes. Leave vanilla
  featured-prize groups alone when the randomized prize path is selected.
- Use dev's item-info, item-get, file and flag managers, with separate saved
  prize-completion flags.
- Retain the existing final-reward event patch.

Shell and shop source, their lists and their behavior are unchanged from dev.
No native hooks, additional subsdk module, patched main, dependency changes,
build-system changes or Archipelago code are included.

## Verification

A fresh real seed generated through dev's normal UI settings, shuffler and
entire generator, with Few traps enabled and the original upstream dev runtime.
All five targeted tests passed without skips against that output:
checkbox/settings, checked versus unchecked pool membership, trap presentation,
prize rows/models/flags/gates and the six collection-event branches.

Run `python tests/generate_trendy_smoke_mod.py --romfs PATH --output NEW_FOLDER`
to reproduce generation. Set LAS_TEST_MOD to the printed game directory, then
run `python -m unittest discover -s tests -v`.

No gameplay test has been performed for this dev port. Test entry/re-entry,
all six prizes, collection order, repeat prizes, figurines, final reward and
save/reload before updating the PR. No full-playthrough stability claim is made.

No game files, runtime binaries, keys, saves or generated output are included.
