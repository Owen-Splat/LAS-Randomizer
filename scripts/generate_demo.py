"""Real AP framework generation and server multidata for local development."""
import argparse
import copy
import json
from pathlib import Path
import zlib

from ap_bootstrap import ROOT, load_ap


def multidata(multiworld):
    from NetUtils import NetworkSlot, SlotType
    from Utils import version_tuple
    import worlds
    players = multiworld.player_ids
    return {"slot_data": {p: multiworld.worlds[p].fill_slot_data() for p in players},
            "slot_info": {p: NetworkSlot(multiworld.player_name[p], multiworld.game[p], SlotType.player) for p in players},
            "connect_names": {multiworld.player_name[p]: (0, p) for p in players},
            "locations": {p: {loc.address: (loc.item.code, loc.item.player, loc.item.flags)
                              for loc in multiworld.get_filled_locations(p) if type(loc.address) is int} for p in players},
            "checks_in_area": {}, "server_options": {}, "er_hint_data": {},
            "precollected_items": {p: [item.code for item in multiworld.precollected_items[p]] for p in players}, "precollected_hints": {p: set() for p in players},
            "version": tuple(version_tuple), "tags": ["AP"],
            "minimum_versions": {"server": (0, 6, 7), "clients": {p: (0, 6, 7) for p in players}},
            "seed_name": multiworld.seed_name, "spheres": [],
            "datapackage": {game: copy.deepcopy(worlds.network_data_package["games"][game])
                            for game in {"Archipelago", *multiworld.game.values()}}, "race_mode": 0}


def generate(seed=1234, options=None):
    world = load_ap()
    from test.general import setup_multiworld
    from Fill import distribute_items_restrictive
    types = [world]
    mw = setup_multiworld(types, options=options or {}, seed=seed)
    mw.seed_name = f"LAS-development-{seed}" if not options else f"LAS-expanded-{seed}"
    distribute_items_restrictive(mw)
    if not mw.can_beat_game():
        raise ValueError("Generated world fails AP beatability")
    return mw


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument("--out", type=Path, default=ROOT / "build/demo")
    p.add_argument('--profile',choices=('standard','core','all'),default='standard')
    args = p.parse_args()
    if args.out.exists():
        p.error("Choose a new output folder")
    options=None if args.profile=='standard' else {'check_profile':'configured','accessibility':'full',
               'owl_gifts':args.profile=='all','blupsanity':args.profile=='all'}
    mw = generate(args.seed,options)
    args.out.mkdir(parents=True)
    mw.worlds[1].generate_output(str(args.out))
    from Utils import restricted_dumps
    (args.out / "demo.archipelago").write_bytes(bytes([3]) + zlib.compress(restricted_dumps(multidata(mw)), 9))
    spoiler = {p: {loc.name: {"item": loc.item.name, "recipient": loc.item.player}
                   for loc in mw.get_filled_locations(p)} for p in mw.player_ids}
    (args.out / "placements.json").write_text(json.dumps(spoiler, indent=2), encoding="utf-8")
    print(f"Generated {sum(len(mw.get_locations(p)) for p in mw.player_ids)} checks; AP beatable=True")
    print(f"Development seed and .lasap written to {args.out}")
