import json
from pathlib import Path
import tempfile
import unittest

from Fill import distribute_items_restrictive
from test.general import setup_multiworld
from worlds.las_switch import LASWorld
from worlds.las_switch.core.seed import validate_manifest


class RealAPWorldTests(unittest.TestCase):
    def test_three_solo_seeds_fill_beat_and_export(self):
        for number in (1234, 5678, 9001):
            with self.subTest(seed=number):
                mw = setup_multiworld(LASWorld, seed=number)
                mw.seed_name = f"test-{number}"
                self.assertEqual(len(mw.get_locations()), 283)
                self.assertEqual(len(mw.itempool), 283)
                distribute_items_restrictive(mw)
                self.assertTrue(mw.can_beat_game())
                self.assertFalse(mw.get_unfilled_locations())
                for name in ("D6-facade", "D6-instrument", "rapids-south-island"):
                    self.assertFalse(mw.get_location(name, 1).locked)
                with tempfile.TemporaryDirectory() as temp:
                    mw.worlds[1].generate_output(temp)
                    paths = list(Path(temp).glob("*.lasap"))
                    self.assertEqual(len(paths), 1)
                    manifest = validate_manifest(json.loads(paths[0].read_text()))
                    self.assertEqual(len(manifest["placements"]), 283)

    def test_two_las_slots_generation(self):
        mw = setup_multiworld([LASWorld, LASWorld], seed=2026)
        distribute_items_restrictive(mw)
        self.assertTrue(mw.can_beat_game())
        outgoing = [loc for loc in mw.get_locations(1) if loc.item.player == 2]
        incoming = [loc for loc in mw.get_locations(2) if loc.item.player == 1]
        self.assertTrue(outgoing)
        self.assertTrue(incoming)
        with tempfile.TemporaryDirectory() as temp:
            mw.worlds[1].generate_output(temp)
            manifest = validate_manifest(json.loads(next(Path(temp).glob("*.lasap")).read_text()))
            self.assertTrue(all(p["item_game"] == LASWorld.game for p in manifest["placements"]))

    def test_full_accessibility_with_all_categories(self):
        mw=setup_multiworld(LASWorld,options={'accessibility':'full','check_profile':'configured',
                                           'owl_gifts':True,'blupsanity':True},seed=4242)
        self.assertEqual(len(mw.get_locations()),344)
        self.assertEqual(len(mw.itempool),344)
        distribute_items_restrictive(mw)
        self.assertTrue(mw.can_beat_game())
        self.assertFalse(mw.get_unfilled_locations())
        all_state=mw.get_all_state(False)
        self.assertTrue(all(loc.can_reach(all_state) for loc in mw.get_locations()))
        with tempfile.TemporaryDirectory() as temp:
            mw.worlds[1].generate_output(temp)
            manifest=validate_manifest(json.loads(next(Path(temp).glob('*.lasap')).read_text()))
            self.assertEqual(manifest['schema_version'],4)
            self.assertEqual(len(manifest['placements']),344)
