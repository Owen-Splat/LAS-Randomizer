"""Stage exactly one sentinel chest in a NEW isolated native-test mod."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ACTOR = 0x8D003E005D26B298
MARKER = 0x4C415300
RELATIVE = Path("region_common/level/Field/Field_08B.leb")
EXPECTED_HASH = "5ce2c80d576e6bc468ec24cbcf7f57a13ce2a324781b3b209e8eb5c3cbfb9cc2"

def stage(source, romfs, mod):
    if not (mod / "exefs/subsdk9").is_file():
        raise ValueError("Select the isolated reward-test mod, not the normal Ryujinx mods folder")
    report = json.loads((mod.parent / "probe_report.json").read_text())
    if not report.get("isolated_sentinel_suppression_test",report.get("isolated_reward_test")):
        raise ValueError("The native module must be a sentinel-suppression test build")
    destination = mod / "romfs" / RELATIVE
    if destination.exists(): raise ValueError("Chest output already exists; refusing to replace it")
    sys.path.insert(0, str(source.resolve()))
    from RandomizerCore.Tools.leb import Room
    original = (romfs / RELATIVE).read_bytes()
    if hashlib.sha256(original).hexdigest() != EXPECTED_HASH:
        raise ValueError("The chest asset differs from the inspected clean 1.0.0 room")
    room = Room(original)
    chests = [a for a in room.actors if a.type == 0xF7]
    if len(chests) != 1 or chests[0].key != ACTOR:
        raise ValueError("Chest actor identity mismatch")
    switches = list(chests[0].switches)
    room.setChestContent("Rupee50", MARKER)
    patched = room.repack()
    verify = Room(patched)
    chest = next(a for a in verify.actors if a.key == ACTOR)
    if chest.parameters[1:3] != [b"Rupee50", MARKER] or chest.switches != switches:
        raise ValueError("Chest round-trip verification failed")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(patched)
    report = dict(location="woods-south-chest", location_id=1280512342,
                  actor_key=hex(ACTOR), marker=hex(MARKER), original_sha256=EXPECTED_HASH,
                  patched_sha256=hashlib.sha256(patched).hexdigest(),
                  collection_switches_preserved=True, live_collection_verified=False)
    (mod / "chest_probe.json").write_text(json.dumps(report, indent=2))
    return report

if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "romfs", "mod"):p.add_argument("--"+name, type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(stage(a.source, a.romfs, a.mod), indent=2))
