"""Trendy-only integration checks. Set LAS_TEST_MOD for generated-asset checks."""
import copy
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.argv[0] = str(ROOT/'randomizer.py')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication
from RandomizerUI.main_window import MainWindow
from RandomizerCore import randomizer_data as data
from RandomizerCore.shuffler import ItemShuffler
from RandomizerCore.Tools import oead_tools, event_tools
from RandomizerCore.Randomizers.standalone_trendy import DevTrendyRewards

APPLICATION = QApplication.instance() or QApplication([])
BUILD = os.environ.get('LAS_TEST_MOD')

class TrendySettings(unittest.TestCase):
    def test_checkbox_and_settings_enable_all_seven_rewards(self):
        with patch('RandomizerUI.main_window.UpdateProcess.start'):
            window = MainWindow()
        widget = window.ui.findCheckBox('Trendy Game')
        self.assertTrue(widget.isEnabled())
        widget.setChecked(True)
        self.assertTrue(window.settings.fetch()['Settings']['Trendy Game'])
        self.assertEqual(len(data.TRENDY_REWARDS), 7)
        self.assertTrue(set(data.TRENDY_REWARDS) <= data.TOTAL_CHECKS)

    def test_unchecked_rewards_stay_vanilla_and_checked_rewards_shuffle(self):
        with patch('RandomizerUI.main_window.UpdateProcess.start'):
            window = MainWindow()
        for enabled in (False, True):
            settings = window.settings.fetch()
            settings.update(settings.pop('Settings'))
            settings['Trendy Game'] = enabled
            shuffler = ItemShuffler(settings, copy.deepcopy(data.ITEM_DEFS), copy.deepcopy(data.LOGIC_DEFS))
            shuffler.placements = {}
            errors = []
            shuffler.error.connect(errors.append)
            with patch('RandomizerCore.shuffler.ShufflerStartingItems'), patch.object(shuffler, 'addTraps'), patch.object(shuffler, 'shuffleDungeons'), patch.object(shuffler, 'makeRandomizedPlacement'):
                shuffler.run()
            self.assertEqual(errors, [])
            if enabled:
                self.assertTrue(set(data.TRENDY_REWARDS).isdisjoint(shuffler.vanilla_locations))
            else:
                self.assertTrue(set(data.TRENDY_REWARDS) <= shuffler.vanilla_locations)

    def test_trap_model_fallback_does_not_change_the_real_reward(self):
        definitions = {'zap-trap': {'item-key': 'ZapTrap'}}
        generator = SimpleNamespace(rom_path=Path('clean'), romfs_dir=Path('output'), placements={},
                                    item_defs=definitions, item_get_manager=Mock())
        rewards = DevTrendyRewards(generator)
        self.assertEqual(rewards.item_defs['zap-trap']['model-name'], 'RupeeGreen')
        self.assertNotIn('model-name', definitions['zap-trap'])
        rewards.give('flow', 'trendy-prize-1', 'next')
        generator.item_get_manager.get.assert_called_once_with('flow', 'trendy-prize-1', after='next', force_anim=True)

@unittest.skipUnless(BUILD, 'Set LAS_TEST_MOD to a generated dev game directory')
class TrendyGeneratedAssets(unittest.TestCase):
    def setUp(self):
        self.root = Path(BUILD)/'romfs/region_common'

    def test_prize_rows_models_flags_and_repeat_gates(self):
        rows = oead_tools.readSheet(self.root/'datasheets/CranePrize.gsheet')['values']
        self.assertEqual(len(rows), 27)
        self.assertTrue(all(len(row['layouts']) for row in rows))
        flags = oead_tools.readSheet(self.root/'datasheets/GlobalFlags.gsheet')['values']
        symbols = {row['symbol'] for row in flags}
        self.assertTrue({'LAS_CraneOriginalOff'} | {f'LAS_CranePrize{i}' for i in range(1, 7)} <= symbols)
        for index, row in enumerate(rows[-6:], 1):
            self.assertFalse(row['options']['isAutoSave'])
            self.assertEqual(row['layouts'][0]['itemIndex'], 0x53430000+index)
            self.assertTrue((self.root/'actor'/f"Prize{row['symbol']}.bfres").is_file())
            self.assertIn('!LAS_CranePrize'+str(index), [condition['parameter'] for condition in row['layouts'][0]['conditions']])
        for row in rows[:21]:
            if row['symbol'] in ('YoshiDoll', 'HeartPiece', 'SecretSeashell', 'PanelDungeonPiece'):
                self.assertTrue(all('LAS_CraneOriginalOff' in [condition['parameter'] for condition in layout['conditions']] for layout in row['layouts']))
        # Dev's shuffled-bomb and shield availability rules must survive the port.
        shield = next(row for row in rows if row['symbol'] == 'Shield')
        self.assertIn('ShieldFoundFlag', [condition['parameter'] for condition in shield['layouts'][0]['conditions']])

    def test_each_prize_records_its_own_collection_flag(self):
        flow = event_tools.readFlow(self.root/'event/PrizeCommon.bfevfl')
        parameters = [event.data.params.data for event in flow.flowchart.events if getattr(event.data, 'params', None) is not None]
        for index in range(1, 7):
            self.assertTrue(any(parameter.get('symbol') == f'LAS_CranePrize{index}' and parameter.get('value') is True for parameter in parameters))
            # The real dev query returns the raw itemIndex, not an equality bit.
            dispatch = [event for event in flow.flowchart.events
                        if getattr(event.data, 'cases', None) is not None and
                        getattr(event.data, 'params', None) is not None and
                        event.data.params.data.get('value1') == 'itemIndex' and
                        0x53430000+index in event.data.cases]
            self.assertEqual(len(dispatch), 1)
            self.assertNotIn('value2', dispatch[0].data.params.data)
            reward = dispatch[0].data.cases[0x53430000+index].v
            self.assertIsNotNone(reward)
            self.assertNotEqual(reward.name, 'Event0')

if __name__ == '__main__':
    unittest.main()
