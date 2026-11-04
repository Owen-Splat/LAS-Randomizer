import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / ".deps"))
from las_ap.catalog import load_catalog
from las_ap.manifest import GAME, example, plan, validate
from las_ap.simulation import ReceivedHistory, SimulatedGame


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_catalog(ROOT.parent / "reference_sources/LAS-Randomizer-0.41")

    def setUp(self):
        self.manifest = example(self.catalog)

    def test_checked_in_catalog_matches_source_and_ids_are_unique(self):
        stored = json.loads((ROOT / "data/catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(stored, self.catalog)
        for table in (self.catalog["items"], self.catalog["locations"]):
            self.assertEqual(len(table), len({x["prototype_id"] for x in table.values()}))

    def test_plan_is_deterministic_does_not_mutate_and_suppresses_foreign_reward(self):
        original = copy.deepcopy(self.manifest)
        first = plan(self.manifest, self.catalog)
        self.assertEqual(first, plan(self.manifest, self.catalog))
        self.assertEqual(self.manifest, original)
        self.assertFalse(first["deployable"])
        action = first["actions"][0]
        self.assertEqual(action["room_basename"], "Field_08B.leb")
        self.assertIn("suppress", action["local_reward_policy"])
        self.assertEqual(action["reward"]["recipient_slot"], 2)

    def test_local_reward_is_also_deferred_to_received_history(self):
        self.manifest["placements"][0]["reward"] = {
            "recipient_slot": 1, "game": GAME, "item": "feather",
            "item_id": self.catalog["items"]["feather"]["prototype_id"]}
        self.assertIn("suppress", plan(self.manifest, self.catalog)["actions"][0]["local_reward_policy"])

    def test_reject_wrong_source_ids_options_slots_and_unreviewed_check(self):
        cases = []
        m = copy.deepcopy(self.manifest); m["source_digest"] = "wrong"; cases.append(m)
        m = copy.deepcopy(self.manifest); m["placements"][0]["location_id"] = "wrong"; cases.append(m)
        m = copy.deepcopy(self.manifest); m["identity"]["slot"] = True; cases.append(m)
        m = copy.deepcopy(self.manifest); m["options"]["shuffle_dungeons"] = True; cases.append(m)
        m = copy.deepcopy(self.manifest); m["options"]["traps"] = 0; cases.append(m)
        m = copy.deepcopy(self.manifest); m["placements"].append(copy.deepcopy(m["placements"][0])); cases.append(m)
        m = copy.deepcopy(self.manifest); m["placements"][0]["location"] = "D1-button-chest"; cases.append(m)
        for manifest in cases:
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                validate(manifest, self.catalog)


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "game.sqlite"
        self.identity = {"seed": "s", "slot": 1, "save_id": "a", "manifest": "manifest-digest"}
        self.game = SimulatedGame(self.path, self.identity)
        self.history = ReceivedHistory()

    def tearDown(self):
        self.game.close()
        self.temp.cleanup()

    def test_overlap_is_deduplicated_conflict_and_gap_rejected_atomically(self):
        self.history.ingest(0, ["feather", "shield"])
        self.history.ingest(1, ["shield", "feather"])
        self.assertEqual(self.history.items, ["feather", "shield", "feather"])
        for index, items in ((4, ["shield"]), (0, ["shield"]), (-1, []), (3, ["unknown"])):
            with self.assertRaises(ValueError):
                self.history.ingest(index, items)
        self.assertEqual(self.history.items, ["feather", "shield", "feather"])

    def test_collection_never_grants_original_reward_and_repeated_check_is_safe(self):
        self.game.collect("woods-south-chest")
        self.game.collect("woods-south-chest")
        self.assertEqual(self.game.snapshot(), {"cursor": 0, "inventory": {}, "checks": ["woods-south-chest"]})

    def test_unsafe_state_crash_and_restart(self):
        self.history.ingest(0, ["feather"])
        self.assertFalse(self.game.deliver(self.history, safe=False))
        with self.assertRaises(RuntimeError):
            self.game.deliver(self.history, fail_before_commit=True)
        self.assertEqual(self.game.snapshot()["cursor"], 0)
        self.assertEqual(self.game.snapshot()["inventory"], {})
        self.assertTrue(self.game.deliver(self.history))
        self.game.close()
        self.game = SimulatedGame(self.path, self.identity)
        self.history.ingest(0, ["feather"])
        self.assertFalse(self.game.deliver(self.history))
        self.assertEqual(self.game.snapshot()["inventory"], {"feather": 1})

    def test_wrong_save_identity_is_rejected(self):
        for key, value in (("seed", "other"), ("slot", 2), ("save_id", "b"), ("manifest", "other")):
            changed = dict(self.identity, **{key: value})
            with self.assertRaises(ValueError):
                SimulatedGame(self.path, changed)

    def test_save_rollback_replays_from_restored_game_cursor(self):
        backup = Path(self.temp.name) / "backup.sqlite"
        self.history.ingest(0, ["feather", "shield"])
        self.game.deliver(self.history)
        self.game.backup(backup)
        self.game.deliver(self.history)
        self.game.close()
        with closing(sqlite3.connect(backup)) as source, closing(sqlite3.connect(self.path)) as target:
            source.backup(target)
        self.game = SimulatedGame(self.path, self.identity)
        self.assertTrue(self.game.deliver(self.history))
        self.assertFalse(self.game.deliver(self.history))
        self.assertEqual(self.game.snapshot()["inventory"], {"feather": 1, "shield": 1})


if __name__ == "__main__":
    unittest.main()
