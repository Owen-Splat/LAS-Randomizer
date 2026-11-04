# Link's Awakening Switch Archipelago — 0.4.0 beta

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

The main standalone window now uses the category-enabled source selected by
`gui_source` in local_setup.json. Seashells, Trendy Game and Shop are selectable
and feed standalone generation. They default off pending gameplay validation.
Archipelago generation still uses the pinned `source` and the settings in your
`.lasap`; changing the main window checkboxes does not change an AP seed.
Close any older window and reopen the launcher to load this GUI fix.

Before installing, double-click **Build APWorld.cmd** in this folder. It builds
`las_switch.apworld` from `apworld/las_switch` and replaces any existing copy in
this folder. Wait for the **Built:** message before continuing. Python 3 must
be installed; no game files or extra Python packages are needed for this step.
Rebuild whenever you change the AP world source.

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

Experimental shell ground models are available under **Test native integration
(copied saves only)** via its **Experimental shell ground models** checkbox.
Normal release generation keeps stock ground visuals pending source-family
gameplay validation. The experiment stages all supported indexed shell sources
(33 in the all-check seed), while preserving original actor types, room files,
events and AP receipts. It changes only the original NPC component's visual
definition. Foreign/trap presentations retain the prepared GREG fallback.
Heart-piece visuals remain separate and unchanged. A real CiaoCiao/DogHouse
Nightmare Key ground model and collection were confirmed; other families,
repeated entries and save/load coverage remain incomplete. Selector tests use a
substituted constructor boundary and do not establish scene safety. The old
factory/pool renderer is retired and is never enabled by the new option.

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

Paths in `local_setup.json` resolve relative to that file's folder, regardless
of the working directory: `./gamefiles/romfs`, `./gamefiles/exefs`,
`./output_parent`, `./source` and `./gui_source`. The two source folders are
included. Put your own clean game files into the empty gamefiles folders;
game data is not included. The launcher still uses this PC's existing Python
3.12 environment; another PC needs that launcher path updated and the
patcher/native requirements installed. The AP client is inside the `.apworld`.
Generated game outputs belong outside this source package. No game assets,
generated executables, emulator keys or saves are distributed here.

New code is MIT. Original LAS data/source and LASRecomp-derived helpers retain
the notices in THIRD_PARTY_LAS_LICENSE.txt and vendor/LASRecomp-LICENSE.txt.
