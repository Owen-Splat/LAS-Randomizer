"""Public source-only tests; no game data or AP installation needed."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ElementTree
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
sys.argv[0] = str(PROJECT_ROOT / 'randomizer.py')
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
from PySide6.QtWidgets import QApplication, QMainWindow
from RandomizerUI.UI.ui_form import Ui_MainWindow
from RandomizerUI import settings_manager as settings_manager
from RandomizerCore import randomizer_data
from RandomizerCore.shuffler import ItemShuffler
from RandomizerCore.Randomizers.indexed_pickups import locations
import yaml
# Run the UI tests without opening a visible window.
APPLICATION = QApplication.instance() or QApplication([])
GAME_LOGIC = yaml.safe_load((PROJECT_ROOT / 'RandomizerCore/Data/logic.yml').read_text())

# Start each test with the normal default settings.
def create_test_window():
    test_window = QMainWindow()
    test_window.ui = Ui_MainWindow()
    test_window.ui.setupUi(test_window)
    for name, value in settings_manager.BASE_OPTIONS.items():
        if isinstance(value, bool):
            getattr(test_window.ui, name).setChecked(value)
        elif isinstance(value, int):
            setter_name = 'setCurrentIndex' if name.endswith('ComboBox') else 'setValue'
            getattr(getattr(test_window.ui, name), setter_name)(value)
        else:
            setattr(test_window, name, copy.deepcopy(value))
    test_window.mode = 'dark'
    test_window.excluded_checks = set()
    test_window.overworld_owls = False
    test_window.dungeon_owls = False
    test_window.ui.lineEdit_3.setText('StandaloneChecks')
    return test_window

class CategoryOptions(unittest.TestCase):

    def test_controls_and_designer_are_clickable_and_have_no_disabled_styling(self):
        test_window = create_test_window()
        interface_document = ElementTree.parse(PROJECT_ROOT / 'RandomizerUI/UI/ui_form.ui')
        for name in ('seashellsCheck', 'trendyCheck', 'shopCheck'):
            widget = getattr(test_window.ui, name)
            self.assertTrue(widget.isEnabled())
            self.assertTrue(widget.isCheckable())
            self.assertFalse(widget.font().strikeOut())
            self.assertEqual(widget.styleSheet(), '')
            widget_definition = interface_document.find('.//widget[@name="' + name + '"]')
            self.assertEqual(widget_definition.find('property[@name="checkable"]/bool').text, 'true')
            self.assertEqual(widget_definition.find('property[@name="font"]/font/strikeout').text, 'false')

    def test_check_lists_and_settings_round_trip_include_all_three_categories(self):
        test_window = create_test_window()
        for name in ('seashellsCheck', 'trendyCheck', 'shopCheck'):
            getattr(test_window.ui, name).setChecked(True)
        test_window.excluded_checks = {'taltal-heights-hole', 'trendy-prize-6', 'shop-slot5-7th'}
        randomizer_settings = settings_manager.loadRandomizerSettings(test_window, 'seed')
        for key in ('randomize-shells', 'randomize-trendy', 'randomize-shop'):
            self.assertTrue(randomizer_settings[key])
        self.assertEqual(len(randomizer_data.SHOP_ITEMS), 10)
        self.assertEqual(len(randomizer_data.TRENDY_REWARDS), 7)
        self.assertTrue(set(randomizer_data.SHELL_LOCATIONS) <= randomizer_data.TOTAL_CHECKS)
        encoded = settings_manager.encodeSettings(test_window)
        self.assertTrue(encoded.startswith('LAS2:'))
        decoded = settings_manager.decodeSettings(encoded)
        for name in ('seashellsCheck', 'trendyCheck', 'shopCheck'):
            self.assertTrue(decoded[name])
        self.assertEqual(set(decoded['excluded_locations']), test_window.excluded_checks)

    def test_legacy_settings_strings_are_rejected_instead_of_reinterpreted(self):
        with self.assertRaisesRegex(ValueError, 'LAS2'):
            settings_manager.decodeSettings('old-unversioned-string')

    def test_shuffler_releases_exactly_the_supported_sources_when_enabled(self):
        for enabled in (False, True):
            randomizer_settings = settings_manager.loadRandomizerSettings(create_test_window(), 'source-test')
            randomizer_settings.update({option_name: enabled for option_name in ('randomize-shells', 'randomize-trendy', 'randomize-shop')})
            shuffler = ItemShuffler('', 'seed', 'basic', randomizer_settings, copy.deepcopy(randomizer_data.ITEM_DEFS), copy.deepcopy(GAME_LOGIC))
            errors = []
            shuffler.error.connect(errors.append)
            with patch.object(shuffler, 'logicSettingsChanges'), patch.object(shuffler, 'addStartingItems'), patch.object(shuffler, 'addTraps'), patch.object(shuffler, 'shuffleDungeons'), patch.object(shuffler, 'makeRandomizedPlacement', return_value=({}, None)):
                shuffler.run()
            self.assertEqual(errors, [])
            selected_locations = set(locations(GAME_LOGIC)) | set(randomizer_data.SHOP_ITEMS) | set(randomizer_data.TRENDY_REWARDS)
            self.assertEqual(len(locations(GAME_LOGIC)), 38)
            if enabled:
                self.assertFalse(selected_locations & shuffler.vanilla_locations)
            else:
                self.assertTrue(selected_locations <= shuffler.vanilla_locations)
if __name__ == '__main__':
    unittest.main()
