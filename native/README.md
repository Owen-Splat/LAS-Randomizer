# LAS 1.0.0 native runtime — beta

Build through the patch tools using the user's clean ExeFS. Normal play mode
compiles a candidate, runs test_native.py and verifies all seven protocol proofs
and enabled optional features before publishing a game. validation.py defines
the required proofs. Development builds still advertise no capabilities.

Receipts, checks, indexed/progressive/dungeon rewards, ending signal, DeathLink
and prepared hint dialogs are implemented. Expanded saves use 100 bytes at
0x5E5C; legacy saves use86 bytes at0x5E6A. Seed/save mismatches are rejected.
Fresh-slot binding permits starting items before the first check, while an
already completed vanilla save cannot silently become a completed AP save.

Tests execute compiled ARM64 and real inventory/save routines; some OS/event
services are substituted. Full gameplay validation remains incomplete. Ground
actors retain vanilla graphics in normal release generation. The opt-in
--world-visuals copied-save mode selects a cloned graphics definition in the
original shell NPC component constructor. It never edits actors or grows a
runtime string pool. A real DogHouse ground-model/collection test passed;
all other shell source families still require physical validation. The separate
test_world_visuals.py suite tests selector/asset boundaries, not real rendering.
Never distribute game binaries/assets/keys/saves.
