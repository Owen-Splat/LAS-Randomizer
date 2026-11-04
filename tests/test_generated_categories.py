"""Inspect generated standalone game assets without distributing them.

Set LAS_TEST_MOD to a fresh standalone generated mod folder.
"""
import json
import os
from pathlib import Path
import sys
import unittest
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from RandomizerCore.Tools import oead_tools as sheet_tools, event_tools as event_tools
from RandomizerCore.Tools.msbt import Msbt
GENERATED_MOD_PATH = os.environ.get('LAS_TEST_MOD')

@unittest.skipUnless(GENERATED_MOD_PATH, 'Set LAS_TEST_MOD to inspect private generated game assets')
class GeneratedCategories(unittest.TestCase):

    def setUp(self):
        self.mod_folder = Path(GENERATED_MOD_PATH)
        self.romfs_folder = self.mod_folder / 'romfs'

    def read_sheet(self, name):
        return sheet_tools.readSheet(self.romfs_folder / 'region_common/datasheets' / name)

    def test_shell_visual_definitions_cover_all_indexed_shells(self):
        report = json.loads((self.mod_folder / 'world-pickup-visuals.json').read_text())
        self.assertEqual(report['stock_fallbacks'], [])
        self.assertEqual(len(report['checks']), 33)
        rows = {row['symbol']: row for row in self.read_sheet('Npc.gsheet')['values']}
        original_shell = sheet_tools.parseStruct(rows['ItemSecretSeashell'])
        for check in report['checks']:
            shell_visual = sheet_tools.parseStruct(rows[check['world_npc']])
            self.assertEqual(shell_visual['graphics']['path'], check['model_path'])
            self.assertEqual(shell_visual['graphics']['model'], check['model_name'])
            # Only graphics fields may differ from the original shell.
            shell_visual['symbol'] = original_shell['symbol']
            for field in ('path', 'model', 'drsb'):
                shell_visual['graphics'][field] = original_shell['graphics'][field]
            self.assertEqual(shell_visual, original_shell)

    def test_prize_rows_keep_native_indexes_and_nonempty_layouts(self):
        rows = self.read_sheet('CranePrize.gsheet')['values']
        self.assertEqual(len(rows), 27)
        self.assertTrue(all((len(row['layouts']) for row in rows)))
        for row in rows[-6:]:
            self.assertTrue((self.romfs_folder / 'region_common/actor' / ('Prize' + row['symbol'] + '.bfres')).is_file())
            self.assertFalse(row['options']['isAutoSave'])
            self.assertTrue(row['layouts'][0]['itemIndex'] & 4294901760 == 1396899840)
        for row in rows:
            if row['symbol'] in ('YoshiDoll', 'HeartPiece', 'SecretSeashell', 'PanelDungeonPiece'):
                for layout in row['layouts']:
                    self.assertIn('LAS_CraneOriginalOff', [condition['parameter'] for condition in layout['conditions']])

    def test_all_source_and_pending_flags_are_distinct_and_present(self):
        flags = self.read_sheet('GlobalFlags.gsheet')['values']
        symbols = [row['symbol'] for row in flags]
        indexes = [row['index'] for row in flags]
        self.assertEqual(len(symbols), len(set(symbols)))
        self.assertEqual(len(indexes), len(set(indexes)))
        custom_flags = [row for row in flags if row['symbol'].startswith(('LASPickup_', 'LASShop', 'LAS_Crane'))]
        self.assertEqual(len(custom_flags), 65)
        self.assertTrue(all((1248 <= row['index'] < 2048 for row in custom_flags)))
        sources = json.loads((self.mod_folder / 'native-build/sources.json').read_text())
        self.assertEqual(len(sources), 48)
        self.assertTrue(all((row['flag'] in indexes for row in sources)))

    def test_shop_shelves_prices_and_pending_theft_flows_exist(self):
        read_sheet = self.read_sheet('ShopItem.gsheet')
        goods = [goods_entry for slot in read_sheet['values'] for goods_entry in slot['mGoods'] if goods_entry['mItem'].startswith('LASShopGoods_')]
        self.assertEqual(len(goods), 10)
        items = self.read_sheet('Items.gsheet')['values']
        dummies = [row for row in items if row['symbol'].startswith('LASShopGoods_')]
        self.assertEqual({row['itemID'] for row in dummies}, set(range(230, 240)))
        self.assertFalse(any((row['symbol'].startswith('AP_') for row in items)))
        files = list(self.romfs_folder.rglob('System.msbt'))
        self.assertTrue(files)
        for path in files:
            messages = Msbt(path.read_bytes())
            for shop_index in range(10):
                self.assertIn('LASShopGoods_' + str(shop_index) + '_Price', messages.texts)
                self.assertIn('LASShopGoods_' + str(shop_index) + '_Buy', messages.texts)
        flow = event_tools.readFlow(self.romfs_folder / 'region_common/event/PlayerStart.bfevfl')
        parameters = [event.data.params.data for event in flow.flowchart.events if getattr(event.data, 'params', None) is not None]
        for shop_index in range(10):
            self.assertTrue(any((event_parameters.get('symbol') == 'LASShopPending_' + str(shop_index) for event_parameters in parameters)))

    def test_real_indexed_event_grants_are_tagged_and_no_ap_markers_are_present(self):
        tagged_grant_count = 0
        for path in self.romfs_folder.rglob('*.bfevfl'):
            flow = event_tools.readFlow(path)
            for event in flow.flowchart.events:
                event_data = event.data
                if getattr(event_data, 'params', None) is None:
                    continue
                event_parameters = event_data.params.data
                index = event_parameters.get('index')
                if not isinstance(index, int):
                    continue
                self.assertFalse(1279328256 <= index < 1279459328)
                if hasattr(event_data, 'actor_action') and event_data.actor_action.v.v == 'AddItemByKey' and (event_parameters.get('itemKey') in ('Seashell', 'HeartPiece')) and (index >= 0):
                    self.assertEqual(index & 4294901760, 1397161984)
                    tagged_grant_count += 1
        self.assertGreater(tagged_grant_count, 0)
if __name__ == '__main__':
    unittest.main()
