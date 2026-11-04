"""Public source-only tests; no game data or AP installation needed."""
import copy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.argv[0]=str(ROOT/'randomizer.py')
os.environ.setdefault('QT_QPA_PLATFORM','offscreen')
from PySide6.QtWidgets import QApplication,QMainWindow
from RandomizerUI.UI.ui_form import Ui_MainWindow
from RandomizerUI import settings_manager as settings
from RandomizerCore import randomizer_data as data
from RandomizerCore.shuffler import ItemShuffler
from RandomizerCore.Randomizers.indexed_pickups import locations
import yaml

APP=QApplication.instance() or QApplication([])
LOGIC=yaml.safe_load((ROOT/'RandomizerCore/Data/logic.yml').read_text())

def window():
    w=QMainWindow();w.ui=Ui_MainWindow();w.ui.setupUi(w)
    for name,value in settings.BASE_OPTIONS.items():
        if isinstance(value,bool):getattr(w.ui,name).setChecked(value)
        elif isinstance(value,int):
            method='setCurrentIndex' if name.endswith('ComboBox') else 'setValue'
            getattr(getattr(w.ui,name),method)(value)
        else:setattr(w,name,copy.deepcopy(value))
    w.mode='dark';w.excluded_checks=set();w.overworld_owls=False;w.dungeon_owls=False
    w.ui.lineEdit_3.setText('StandaloneChecks')
    return w

class CategoryOptions(unittest.TestCase):
    def test_controls_and_designer_are_clickable_and_have_no_disabled_styling(self):
        w=window();xml=ET.parse(ROOT/'RandomizerUI/UI/ui_form.ui')
        for name in ('seashellsCheck','trendyCheck','shopCheck'):
            widget=getattr(w.ui,name)
            self.assertTrue(widget.isEnabled());self.assertTrue(widget.isCheckable())
            self.assertFalse(widget.font().strikeOut());self.assertEqual(widget.styleSheet(),'')
            node=xml.find('.//widget[@name="'+name+'"]')
            self.assertEqual(node.find('property[@name="checkable"]/bool').text,'true')
            self.assertEqual(node.find('property[@name="font"]/font/strikeout').text,'false')

    def test_check_lists_and_settings_round_trip_include_all_three_categories(self):
        w=window()
        for name in ('seashellsCheck','trendyCheck','shopCheck'):getattr(w.ui,name).setChecked(True)
        w.excluded_checks={'taltal-heights-hole','trendy-prize-6','shop-slot5-7th'}
        mod=settings.loadRandomizerSettings(w,'seed')
        for key in ('randomize-shells','randomize-trendy','randomize-shop'):self.assertTrue(mod[key])
        self.assertEqual(len(data.SHOP_ITEMS),10);self.assertEqual(len(data.TRENDY_REWARDS),7)
        self.assertTrue(set(data.SHELL_LOCATIONS)<=data.TOTAL_CHECKS)
        encoded=settings.encodeSettings(w)
        self.assertTrue(encoded.startswith('LAS2:'))
        decoded=settings.decodeSettings(encoded)
        for name in ('seashellsCheck','trendyCheck','shopCheck'):self.assertTrue(decoded[name])
        self.assertEqual(set(decoded['excluded_locations']),w.excluded_checks)

    def test_legacy_settings_strings_are_rejected_instead_of_reinterpreted(self):
        with self.assertRaisesRegex(ValueError,'LAS2'):settings.decodeSettings('old-unversioned-string')

    def test_shuffler_releases_exactly_the_supported_sources_when_enabled(self):
        for enabled in (False,True):
            mod=settings.loadRandomizerSettings(window(),'source-test')
            mod.update({k:enabled for k in ('randomize-shells','randomize-trendy','randomize-shop')})
            shuffler=ItemShuffler('', 'seed','basic',mod,copy.deepcopy(data.ITEM_DEFS),copy.deepcopy(LOGIC))
            errors=[];shuffler.error.connect(errors.append)
            with patch.object(shuffler,'logicSettingsChanges'),patch.object(shuffler,'addStartingItems'),patch.object(shuffler,'addTraps'),patch.object(shuffler,'shuffleDungeons'),patch.object(shuffler,'makeRandomizedPlacement',return_value=({},None)):
                shuffler.run()
            self.assertEqual(errors,[])
            sources=set(locations(LOGIC))|set(data.SHOP_ITEMS)|set(data.TRENDY_REWARDS)
            self.assertEqual(len(locations(LOGIC)),38)
            if enabled:self.assertFalse(sources&shuffler.vanilla_locations)
            else:self.assertTrue(sources<=shuffler.vanilla_locations)

if __name__=='__main__':unittest.main()
