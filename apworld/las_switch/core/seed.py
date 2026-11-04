"""Versioned multiworld seed format; AP numeric IDs use a frozen local registry."""
import hashlib
import json
from collections import Counter

from .data import GAME, VERSION, CATALOG, ITEM_IDS, LOCATION_IDS, ITEMS, FLAGS, INDEX_POOLS, active_locations, CATEGORY_NAMES, CORE_CATEGORIES, category_flags


def sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def default_save_id(manifest):
    return f"{manifest['identity']['seed']}:{manifest['identity']['slot']}:{manifest['manifest_digest'][:16]}"


def canonical_manifest(manifest):
    result = dict(manifest)
    result.pop("manifest_digest", None)
    return result


def make_manifest(identity, profile, placements, categories=None, settings=None, entrances=None, player_names=None, hint_routes=None):
    manifest = {"schema_version": 2, "game": GAME, "world_version": VERSION,
                "identity": identity, "source_digest": CATALOG["source_digest"],
                "profile": profile, "settings_flags": FLAGS,
                "placements": sorted(placements, key=lambda p: p["location_id"]),
                "starting_items": [], "entrance_shuffle": False,
                "delivery_policy": "all_managed_rewards_via_ap", "runtime_required": True}
    if profile=='configured':
        manifest['schema_version']=3
        manifest['location_categories']=sorted(CORE_CATEGORIES if categories is None else categories)
        manifest['settings_flags']=category_flags(manifest['location_categories'])
    if settings is not None:
        from .configuration import validate,las_settings,DUNGEONS
        validate(settings)
        manifest.update(schema_version=4,player_settings=settings,settings_flags=las_settings(categories,settings),
                        starting_items=settings['starting_items'],entrance_shuffle=settings['shuffled_dungeons'],
                        dungeon_entrances=entrances or {d:d for d in DUNGEONS})
        manifest['player_names']=player_names or {str(identity['slot']):identity['slot_name']}
        manifest['hint_routes']=hint_routes or []
    manifest["manifest_digest"] = sha(manifest)
    return validate_manifest(manifest)


def validate_manifest(manifest):
    if not isinstance(manifest, dict) or manifest.get("schema_version") not in (2,3,4) or manifest.get("game") != GAME:
        raise ValueError("Wrong game or manifest format")
    if manifest.get("manifest_digest") != sha(canonical_manifest(manifest)):
        raise ValueError("Manifest digest mismatch")
    if manifest.get("source_digest") != CATALOG["source_digest"]:
        raise ValueError("Source data mismatch")
    identity = manifest.get("identity", {})
    if (not isinstance(identity.get("seed"), str) or not identity["seed"] or
            type(identity.get("slot")) is not int or identity["slot"] < 1 or
            not isinstance(identity.get("slot_name"), str) or not identity["slot_name"]):
        raise ValueError("Invalid player identity")
    modern=manifest['schema_version']==4
    configured=manifest.get('profile')=='configured' and manifest['schema_version'] in (3,4)
    categories=manifest.get('location_categories')
    if configured:
        if (manifest.get('profile')!='configured' or not isinstance(categories,list) or
                categories!=sorted(set(categories)) or not set(categories)<=CATEGORY_NAMES):
            raise ValueError('Invalid configured check categories')
    elif manifest.get('profile')=='configured' or categories is not None:
        raise ValueError('Configured checks require manifest version 3')
    if modern:
        from .configuration import validate,las_settings,selected_locations,DUNGEONS
        settings=validate(manifest.get('player_settings'))
        entrances=manifest.get('dungeon_entrances')
        if (not isinstance(entrances,dict) or set(entrances)!=set(DUNGEONS) or set(entrances.values())!=set(DUNGEONS) or
                (not settings['shuffled_dungeons'] and any(k!=v for k,v in entrances.items()))):
            raise ValueError('Invalid dungeon entrance permutation')
        if (manifest.get('starting_items')!=settings['starting_items'] or manifest.get('entrance_shuffle')!=settings['shuffled_dungeons'] or
                manifest.get('settings_flags')!=las_settings(categories,settings)):
            raise ValueError('Player settings differ from generator settings')
        names=manifest.get('player_names');hints=manifest.get('hint_routes')
        if not isinstance(names,dict) or any(not isinstance(k,str) or not k.isdigit() or int(k)<1 or str(int(k))!=k or not isinstance(v,str) or not v for k,v in names.items()):
            raise ValueError('Invalid player names')
        if not isinstance(hints,list) or len(hints)>1024:raise ValueError('Too many in-game hint routes')
        seen_hints=set()
        for index,hint in enumerate(hints):
            if not isinstance(hint,dict) or set(hint)!={'index','finding_player','location_id','recipient_slot','item_id','item_name','item_game','location_name','finding_name','recipient_name'}:
                raise ValueError('Invalid in-game hint route')
            if any(type(hint[k]) is not int for k in ('index','finding_player','location_id','recipient_slot','item_id')):
                raise ValueError('Invalid hint identity type')
            key=(hint['finding_player'],hint['location_id'],hint['recipient_slot'],hint['item_id'])
            if (hint['index']!=index or key in seen_hints or hint['finding_player']<1 or hint['recipient_slot']<1 or
                    any(not isinstance(hint[k],str) or not hint[k] for k in ('item_name','item_game','location_name','finding_name','recipient_name'))):
                raise ValueError('Invalid or duplicate hint identity')
            seen_hints.add(key)
    elif (manifest.get("starting_items") != [] or manifest.get("entrance_shuffle") is not False or
            manifest.get("settings_flags") != (category_flags(categories) if configured else FLAGS) or
            manifest.get("delivery_policy") != "all_managed_rewards_via_ap" or manifest.get("runtime_required") is not True):
        raise ValueError("Unsupported generation settings")
    if manifest.get('delivery_policy')!='all_managed_rewards_via_ap' or manifest.get('runtime_required') is not True:
        raise ValueError('Unsupported delivery policy')
    active = set(selected_locations(manifest.get('profile'),categories,settings) if modern else active_locations(manifest.get("profile"),categories))
    rows = manifest.get("placements")
    if not isinstance(rows, list) or len(rows) != len(active):
        raise ValueError("Incomplete placement map")
    seen = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"location", "location_id", "recipient_slot", "item_id", "item_name", "item_game"}:
            raise ValueError("Invalid placement row")
        name = row["location"]
        if name not in active or name in seen or row["location_id"] != LOCATION_IDS[name]:
            raise ValueError("Duplicate, unsupported or mismatched location")
        seen.add(name)
        if type(row["recipient_slot"]) is not int or row["recipient_slot"] < 1 or type(row["item_id"]) is not int:
            raise ValueError("Invalid network item")
        if not all(isinstance(row[key], str) and row[key] for key in ("item_name", "item_game")):
            raise ValueError("Invalid item metadata")
        if row["item_game"] == GAME and ITEM_IDS.get(row["item_name"]) != row["item_id"]:
            raise ValueError("LAS item ID mismatch")
        if row["recipient_slot"] == identity["slot"] and row["item_game"] != GAME:
            raise ValueError("Foreign-game item assigned to this LAS slot")
    return manifest


def patch_bundle(manifest):
    validate_manifest(manifest)
    actions = []
    for row in manifest["placements"]:
        node = CATALOG["locations"][row["location"]]
        actions.append({**row, "subtype": node["definition"]["subtype"],
                        "room_basename": f"{node['chest_room']}.leb" if node["chest_room"] else None,
                        "check_symbol": f"LAS_AP_CHECK_{row['location_id']}",
                        "suppress_direct_reward": True})
    return {"schema_version": 1, "manifest": manifest, "actions": actions,
            "deployable": False, "requires_native_hooks": True,
            "runtime_config": {"protocol": 1, "bridge_host": "127.0.0.1", "bridge_port": 17778,
                               "identity": manifest["identity"], "manifest_digest": manifest["manifest_digest"]}}


def grant_payload(item_id, receipt_index, received_history):
    inverse = {value: name for name, value in ITEM_IDS.items()}
    if item_id not in inverse:
        raise ValueError(f"Unknown LAS item ID: {item_id}")
    name = inverse[item_id]
    definition = ITEMS[name]
    payload = {"item_id": item_id, "item_name": name, "item_key": definition["item-key"],
               "receipt_index": receipt_index, "collectible_index": -1,
               "dungeon": int(name[-1]) if name.startswith(("key-D", "nightmare-key-D", "map-D", "compass-D", "stone-beak-D")) else None,
               "semantic": "las_event_reward", "count": 1}
    if name in INDEX_POOLS:
        # Allocate indexes to deliveries in canonical order, reserving all vanilla
        # indexes is a patcher responsibility. Native hook must use AP-owned storage
        # or the reserved mapping, never assume this ordinal is a vanilla index.
        payload["collectible_index"] = None
        payload["ap_item_ordinal"] = sum(1 for value in received_history[:receipt_index] if value == item_id)
    if name in {"sword", "shield", "bracelet"}:
        payload["semantic"] = "progressive"
    elif name.endswith("-capacity"):
        payload["semantic"] = "capacity_upgrade"
    elif name.startswith(("key-D", "nightmare-key-D", "map-D", "compass-D", "stone-beak-D")):
        payload["semantic"] = "dungeon_item"
    return payload
