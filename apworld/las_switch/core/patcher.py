"""Full vanilla-baseline generator contract plus gated native deployment.

The native bridge suppresses managed local rewards; AP owns their actual items.
The baseline intentionally does not inject unknown AP item keys into LAS files.
"""
from copy import deepcopy
from importlib.resources import files
import hashlib
import json
from pathlib import Path

from .data import CATALOG, ITEMS, NODES, FLAGS, active_locations, content
from .seed import validate_manifest, patch_bundle

DUNGEONS = ("tail-cave", "bottle-grotto", "key-cavern", "angler-tunnel", "catfish-maw",
            "face-shrine", "eagle-tower", "turtle-rock", "color-dungeon")


def generator_contract(manifest):
    validate_manifest(manifest)
    settings = {name: False for name in (
        "create-spoiler", "free-book", "extended-consumable-drop", "unlocked-bombs", "shuffle-bombs",
        "shuffle-powder", "fast-fishing", "fast-stealing", "fast-songs", "shuffle-instruments", "bad-pets",
        "open-kanalet", "open-bridge", "open-mamu", "blupsanity", "classic-d2", "owl-overworld-gifts",
        "owl-dungeon-gifts", "fast-stalfos", "seashells-important", "trade-important", "randomize-music",
        "open-mabe", "boss-cutscenes", "randomize-enemies", "randomize-enemy-sizes", "shuffle-dungeons",
        "blur-removal", "OHKO", "lv1-beam", "nice-rod", "nice-bombs", "fast-chests", "fast-keys")}
    settings.update(manifest["settings_flags"])
    settings.update({"seed": manifest["identity"]["seed"], "logic": "basic", "platform": "emulator",
                     "dungeon-items": "none", "starting-instruments": 0, "traps": "none",
                     "chest-aspect": "default", "stealing": "normal", "starting-items": [],
                     "starting-rupees": 0, "excluded-locations": [], "shuffle-instruments": True,
                     "extended-consumable-drop": True})
    if manifest['schema_version']==4:
        settings.update(manifest['settings_flags'])
        # Pool mutations happened in AP. LAS receives physical placeholders and
        # must never re-shuffle, add traps or grant starting inventory again.
        settings.update({'traps':'none','starting-items':[],'starting-instruments':0})
    placements = {name: content(name) for name, node in NODES.items() if node["type"] == "item"}
    indexes = {name: node["index"] for name, node in NODES.items() if node["type"] == "item" and "index" in node}
    placements.update({"settings": settings, "force-junk": [], "force-vanilla": sorted(placements),
                       "starting-items": [], "dungeon-entrances": manifest.get('dungeon_entrances',{d: d for d in DUNGEONS}), "indexes": indexes,
                       "moblin-cave": "bow-wow", "rooster-statue": "rooster"})
    return {"schema_version": 1, "source_digest": CATALOG["source_digest"],
            "mode": "vanilla_baseline_with_native_ap_suppression", "placements": placements,
            "item_defs": deepcopy(ITEMS), "random_seed": manifest["identity"]["seed"],
            "native_config": patch_bundle(manifest)}


def check_source(source):
    source = Path(source).resolve()
    # Accept only the upstream source or these exact reviewed cleanup versions.
    # Keep the upstream catalog identity stable for existing generated seeds.
    cleanups = json.loads(files(__package__).joinpath('source_cleanup_hashes.json').read_text(encoding='utf-8'))
    for name, expected in CATALOG["fingerprints"].items():
        path = source / name
        allowed_hashes = {expected}
        cleanup = cleanups.get(name)
        if cleanup and cleanup['upstream'] == expected:
            allowed_hashes.add(cleanup['cleanup'])
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() not in allowed_hashes:
            raise ValueError(f"LAS source differs from the pinned version: {name}")
    return source


def backend_files(path):
    metadata = json.loads((Path(path) / 'backend.json').read_text(encoding='utf-8'))
    layout = metadata.get('layout', 'npdm_module_v1')
    if layout == 'npdm_module_v1': return ('subsdk9', 'main.npdm')
    if layout == 'patched_main_module_v1': return ('main', 'subsdk9')
    raise ValueError('Unknown native backend layout')


def verify_backend(path, manifest, build_id, clean_main_sha256=None, save_id=None, team=None):
    """Validate user-supplied native module metadata; never certify its behaviour."""
    path = Path(path).resolve()
    metadata = json.loads((path / "backend.json").read_text(encoding="utf-8"))
    required = {"atomic_delivery_v1", "persistent_checks_v1", "reward_suppression_v1", "victory_v1",
                "indexed_rewards_v1", "progressive_rewards_v1", "dungeon_rewards_v1"}
    if (metadata.get("protocol") != 1 or metadata.get("build_id") != build_id or
            metadata.get("source_digest") != manifest["source_digest"] or
            not required.issubset(metadata.get("capabilities", []))):
        raise ValueError("Native backend version/build/capabilities mismatch")
    expected = {row["location_id"] for row in manifest["placements"]}
    if not expected.issubset(metadata.get("supported_location_ids", [])):
        raise ValueError("Native backend cannot suppress/report all managed checks")
    from .data import ITEM_IDS
    if not set(ITEM_IDS.values()).issubset(metadata.get("supported_item_ids", [])):
        raise ValueError("Native backend does not support all registered LAS item semantics")
    names = backend_files(path)
    if 'main' in names and (not clean_main_sha256 or
                            metadata.get('original_main_sha256') != clean_main_sha256):
        raise ValueError('Native patched main does not match the clean executable')
    if 'main' in names and (metadata.get('manifest_digest') != manifest['manifest_digest'] or
                            not save_id or metadata.get('save_id') != save_id or
                            type(team) is not int or metadata.get('team') != team):
        raise ValueError('Native patched main seed/save/team binding mismatch')
    for name in names:
        binary = path / name
        if not binary.is_file() or hashlib.sha256(binary.read_bytes()).hexdigest() != metadata.get("files", {}).get(name):
            raise ValueError(f"Native backend binary missing or hash mismatch: {name}")
    return path
