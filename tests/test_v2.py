from collections import Counter, namedtuple
from contextlib import closing
import copy
import importlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apworld"))
PKG = "worlds.las_switch" if "worlds.las_switch" in sys.modules else "las_switch"
data = importlib.import_module(PKG + ".core.data")
logic = importlib.import_module(PKG + ".core.logic")
seed = importlib.import_module(PKG + ".core.seed")
runtime = importlib.import_module(PKG + ".core.runtime")
patcher = importlib.import_module(PKG + ".core.patcher")
mock = importlib.import_module(PKG + ".mock_game")
NetworkItem = namedtuple("NetworkItem", "item location player")


def fixture():
    rows = [{"location": name, "location_id": data.LOCATION_IDS[name], "recipient_slot": 1,
             "item_id": data.ITEM_IDS[data.content(name)], "item_name": data.content(name), "item_game": data.GAME}
            for name in data.active_locations()]
    return seed.make_manifest({"seed": "test-seed", "slot": 1, "slot_name": "Link"}, "standard", rows)


class CoreV2Tests(unittest.TestCase):
    def test_configured_categories_cover_all_checks_and_round_trip(self):
        categories=sorted(data.CATEGORY_NAMES)
        names=data.active_locations('configured',categories)
        self.assertEqual(len(names),344)
        self.assertEqual(set(names),set(data.LOCATION_IDS))
        default=data.active_locations('configured')
        self.assertEqual(len(default),283)
        self.assertFalse(any(data.CATEGORIES[n] in {'owl_gifts','blupsanity'} for n in default))
        for category in categories:
            selected=data.active_locations('configured',[category])
            self.assertTrue(selected)
            self.assertTrue(all(data.CATEGORIES[n]==category for n in selected))
        rows=[{'location':name,'location_id':data.LOCATION_IDS[name],'recipient_slot':1,
               'item_id':data.ITEM_IDS[data.content(name)],'item_name':data.content(name),'item_game':data.GAME}
              for name in names]
        manifest=seed.make_manifest({'seed':'all-categories','slot':1,'slot_name':'Link'},'configured',rows,categories)
        self.assertEqual(manifest['schema_version'],3)
        self.assertEqual(seed.validate_manifest(manifest),manifest)
        self.assertTrue(manifest['settings_flags']['blupsanity'])
        contract=patcher.generator_contract(manifest)
        self.assertTrue(contract['placements']['settings']['owl-dungeon-gifts'])
        solver=logic.Logic('configured',categories)
        reach=solver.reachable(tuple(sorted(Counter(data.pool('configured',categories)).items())))
        self.assertFalse(set(names)-reach)

    def test_safe_parser_precedence_counts_and_rejection(self):
        expression = logic.parse("sword:2 & (boots | !shield)")
        self.assertTrue(logic.evaluate(expression, {"sword": 2}))
        self.assertFalse(logic.evaluate(expression, {"sword": 1, "boots": 1}))
        for text in ("__import__('os')", "sword && boots", "(sword", "sword + boots", "", "sword)"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                logic.parse(text)

    def test_all_source_conditions_parse_without_eval_and_known_chest_requires_bracelet(self):
        solver = logic.Logic()
        self.assertGreater(len(solver.conditions), 500)
        self.assertFalse(solver.can_reach(Counter(sword=1), "woods-south-chest"))
        self.assertTrue(solver.can_reach(Counter(sword=1, bracelet=1), "woods-south-chest"))

    def test_registry_and_pool_mapping(self):
        self.assertEqual(len(data.ITEM_IDS), 115)
        self.assertEqual(len(data.LOCATION_IDS), 344)
        self.assertEqual(len(data.active_locations()), 228)
        self.assertEqual(len(data.pool()), 228)
        self.assertTrue(set(data.pool()) <= set(data.ITEMS))
        self.assertEqual(len(set(data.ITEM_IDS.values()) | set(data.LOCATION_IDS.values())), 459)

    def test_full_inventory_goal_and_all_standard_checks_reachable(self):
        solver = logic.Logic()
        reach = solver.reachable(tuple(sorted(Counter(data.pool()).items())))
        self.assertIn("kill-nightmare", reach)
        self.assertEqual(set(data.active_locations()) - reach, set())

    def test_face_shrine_routes_keep_required_equipment_and_keys(self):
        solver=logic.Logic()
        inventory=Counter(data.pool())
        for name in ('D6-facade','D6-instrument','rapids-south-island'):
            self.assertTrue(solver.can_reach(inventory,name))
        without_bracelet=inventory.copy();without_bracelet['bracelet']=1
        self.assertFalse(solver.can_reach(without_bracelet,'rapids-south-island'))
        for item in ('hookshot','nightmare-key-D6'):
            missing=inventory.copy();missing[item]=0
            for name in ('D6-facade','D6-instrument'):
                self.assertFalse(solver.can_reach(missing,name))
        missing=inventory.copy();missing['key-D6']=2
        self.assertFalse(solver.can_reach(missing,'D6-facade'))

    def test_manifest_tampering_duplicate_remote_and_local_rewards(self):
        manifest = fixture()
        original = copy.deepcopy(manifest)
        self.assertEqual(seed.validate_manifest(manifest), original)
        tampered = copy.deepcopy(manifest); tampered["identity"]["slot"] = 2
        with self.assertRaises(ValueError):
            seed.validate_manifest(tampered)
        duplicate = copy.deepcopy(manifest); duplicate["placements"][1] = duplicate["placements"][0]
        duplicate["manifest_digest"] = seed.sha(seed.canonical_manifest(duplicate))
        with self.assertRaises(ValueError):
            seed.validate_manifest(duplicate)
        bundle = seed.patch_bundle(manifest)
        self.assertFalse(bundle["deployable"])
        self.assertTrue(all(a["suppress_direct_reward"] for a in bundle["actions"]))
        self.assertEqual(manifest, original)

    def test_complete_generator_contract_and_source_pin(self):
        contract = patcher.generator_contract(fixture())
        placements = contract["placements"]
        self.assertEqual(placements["woods-south-chest"], "seashell")
        self.assertEqual(placements["indexes"]["woods-south-chest"], 3)
        self.assertEqual(placements["settings"]["platform"], "emulator")
        self.assertFalse(placements["settings"]["shuffle-dungeons"])
        self.assertEqual(placements["moblin-cave"], "bow-wow")
        self.assertTrue(patcher.check_source(ROOT / "source"))
        with tempfile.TemporaryDirectory() as temp, self.assertRaises(ValueError):
            patcher.check_source(temp)

    def test_backend_cannot_be_faked_by_empty_folder(self):
        with tempfile.TemporaryDirectory() as temp:
            (Path(temp) / "backend.json").write_text(json.dumps({"build_id": "wrong"}))
            with self.assertRaises(ValueError):
                patcher.verify_backend(temp, fixture(), "expected")

    def test_cleanup_source_pin_rejects_unapproved_edits(self):
        original_read = Path.read_bytes
        target = ROOT / 'source/RandomizerCore/Randomizers/miscellaneous.py'

        def edited_bytes(path):
            content = original_read(path)
            return content + b'\n# unapproved edit\n' if path == target else content

        with patch.object(Path, 'read_bytes', edited_bytes):
            with self.assertRaisesRegex(ValueError, 'miscellaneous.py'):
                patcher.check_source(ROOT / 'source')

    def test_runtime_replay_and_unknown_history_hash(self):
        manifest = fixture()
        item = NetworkItem(data.ITEM_IDS["feather"], 10, 2)
        state = {"t": "state", "cursor": 0, "history_hash": seed.sha([]), "checks": [], "ready": True, "victory": False}
        action = runtime.next_actions(manifest, state, [item])
        self.assertEqual(action["grant"]["grant"]["item_name"], "feather")
        state["ready"] = False
        self.assertIsNone(runtime.next_actions(manifest, state, [item])["grant"])
        state["cursor"] = 2
        self.assertTrue(runtime.next_actions(manifest, state, [item])["sync_required"])
        state["cursor"] = 1; state["history_hash"] = "wrong"
        with self.assertRaises(ValueError):
            runtime.next_actions(manifest, state, [item])

    def test_indexed_and_progressive_delivery_semantics(self):
        shell = data.ITEM_IDS["seashell"]
        payload = seed.grant_payload(shell, 2, [shell, data.ITEM_IDS["feather"], shell])
        self.assertIsNone(payload["collectible_index"])
        self.assertEqual(payload["ap_item_ordinal"], 1)
        self.assertEqual(seed.grant_payload(data.ITEM_IDS["sword"], 0, [])["semantic"], "progressive")
        key = seed.grant_payload(data.ITEM_IDS["key-D6"], 0, [])
        self.assertEqual((key["dungeon"], key["semantic"]), (6, "dungeon_item"))

    def test_mock_save_failure_and_restart_use_durable_cursor(self):
        manifest = fixture()
        receipt = NetworkItem(data.ITEM_IDS["feather"], 10, 2)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "game.sqlite"
            with closing(mock.MockSave(path, {"id": "test"})) as game:
                action = runtime.next_actions(manifest, game.state(), [receipt])["grant"]
                with self.assertRaises(RuntimeError):
                    game.deliver(action, fail=True)
                self.assertEqual(game.state()["inventory"], {})
                self.assertTrue(game.deliver(action))
                self.assertFalse(game.deliver(action))
            with closing(mock.MockSave(path, {"id": "test"})) as game:
                self.assertEqual(game.state()["inventory"], {"feather": 1})
                self.assertIsNone(runtime.next_actions(manifest, game.state(), [receipt])["grant"])
