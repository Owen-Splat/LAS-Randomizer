# Link's Awakening Switch Archipelago — 0.3.0 beta

The full YAML is `Link_Switch.yaml`. It includes all requested world/logic,
cosmetic, speed, shop and trap settings; Mansion tiers and owl regions; optional
DeathLink; starting quantities; and the 115-type randomized-items whitelist.
Core checks default on. Owl gifts and blupsanity default off.

Starting quantities are removed from the selected pool and replaced with filler.
AP delivers them once through saved receipt history after connecting. Unlisted
item types remain vanilla, and their locations are outside AP. Dungeon entrance
permutations are shared by AP logic and LAS generation. LAS does not shuffle the
AP placements again or grant starting items a second time.

## Use on this PC

1. Install `las_switch.apworld` in AP's custom_worlds folder and restart AP.
2. Generate with `Link_Switch.yaml` (edit player name and settings first).
3. Open **Launch LAS AP Randomizer.cmd**, then **Archipelago → Generate from
   Archipelago patch**. Select your `.lasap`, clean LAS 1.0.0 RomFS/ExeFS, and a
   new output folder. Choose **Generate Archipelago game (beta, verified build)**.
4. The tools build and test the native runtime before publishing
   `ARCHIPELAGO_GAME`. Install that generated mod and use a fresh game save.
5. Open the generated game folder's `seed.lasap` with **LAS Switch Client** in
   AP's launcher and connect to your room. Build/save identity is automatic.

The installed client includes **LAS Status**, **Item History**, **LAS Tracker**
and **Hints**. It shows room/game connections, queued items/checks, sender names,
optional sent-item information and a searchable logic tracker based on delivered
inventory. The standard Hints tab retains AP hint requests, costs and priorities.
Its extra button can display an already-received hint in game; exact server hint
identities are checked, so it cannot reveal additional locations for free.

DeathLink is enabled in YAML and waits for an active game. Received deaths are
not echoed back. Shell ground actors are deliberately unchanged. Foreign items
and synthetic traps use GREG for physical presentation; normal held-up rewards
show their assigned model and recipient message.

## Validation and limits

60 AP/core/client tests pass. The full-options 344-check native beta build ran
44 checks: 38 passed and six were skipped for other diagnostic modes and the
disabled ground renderer. All seven required protocol proofs, DeathLink and
hint tests passed. The exact files are hash-bound to their validation report;
failed validation does not publish a mod.

Earlier live testing confirmed network equipment/rupees, receipt persistence,
shop purchasing, several Trendy prizes and hidden/buried/underwater/bomb-hole
pickups. The newly combined build still needs a fresh-save gameplay check.
A complete playthrough, actual ending, remaining minigames, shop stealing and
physical cross-game play are not fully validated. This is a playable beta,
not a full-playthrough-certified stable release.

Only the inspected clean LAS **1.0.0** executable is supported; disable the
1.0.1 game update. Different seed/storage identities need fresh saves. Existing
output folders are never overwritten. Legacy 228-check and schema 2/3 seeds
remain readable; new generation uses schema 4.

The launcher is configured for this PC's existing Python 3.12 environment and
pinned LAS 0.41 source. If moved, update `local_setup.json` and install the
patcher/native requirements. The AP client itself is inside the `.apworld`.
Generated game outputs belong outside this source package. No game assets,
generated executables, emulator keys or saves are distributed here.

New code is MIT. Original LAS data/source and LASRecomp-derived helpers retain
the notices in THIRD_PARTY_LAS_LICENSE.txt and vendor/LASRecomp-LICENSE.txt.
