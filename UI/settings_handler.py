from randomizer_data import *
import yaml


class MyDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, indentless)


BASE_OPTIONS = {
    'chestsCheck': True,
    'fishingCheck': True,
    'rapidsCheck': False,
    'dampeCheck': False,
    'trendyCheck': False,
    'shopCheck': True,
    'giftsCheck': True,
    'tradeGiftsCheck': False,
    'bossCheck': True,
    'miscellaneousCheck': True,
    'heartsCheck': True,
    'rupCheck': False,
    'instrumentCheck': True,
    'instrumentsComboBox': 0,
    'seashellsComboBox': 2,
    'owlsComboBox': 0,
    'trapsComboBox': 0,
    'leavesCheck': True,
    'tricksComboBox': 0,
    'bookCheck': True,
    'unlockedBombsCheck': True,
    'shuffledBombsCheck': False,
    'fastTrendyCheck': False,
    'stealingCheck': True,
    'farmingCheck': True,
    'shuffledPowderCheck': False,
    'musicCheck': False,
    'enemyCheck': False,
    'enemySizesCheck': False,
    'spoilerCheck': True,
    'kanaletCheck': True,
    'badPetsCheck': False,
    'bridgeCheck': True,
    'mazeCheck': True,
    'swampCheck': False,
    'stalfosCheck': False,
    'chestSizesCheck': False,
    'songsCheck': False,
    'fastFishingCheck': True,
    'dungeonsCheck': False,
    'ohkoCheck': False,
    'lv1BeamCheck': False,
    'niceRodCheck': False,
    'rupeesSpinBox': 0,
    'externalSettingsCheck': False,
    'starting_gear': []
}

EXTRA_OPTIONS = [
    'Theme',
    'Romfs_Folder',
    'Output_Folder',
    'Seed',
    'Platform',
    'External_Settings_File'
]


def applyDefaults(window):
    for k,v in BASE_OPTIONS.items():
        if isinstance(v, bool):
            exec(f"window.ui.{k}.setChecked({v})")
        elif isinstance(v, int):
            if k.endswith('ComboBox'):
                exec(f"window.ui.{k}.setCurrentIndex({v})")
            else:
                exec(f"window.ui.{k}.setValue({v})")
        else:
            exec(f"window.{k} = v")
    
    window.excluded_checks.difference_update(MISCELLANEOUS_CHESTS)
    window.excluded_checks.difference_update(FISHING_REWARDS)
    window.excluded_checks.update(RAPIDS_REWARDS)
    window.excluded_checks.update(DAMPE_REWARDS)
    window.excluded_checks.update(TRENDY_REWARDS)
    # window.excluded_checks.difference_update(SHOP_ITEMS)
    window.excluded_checks.difference_update(FREE_GIFT_LOCATIONS)
    window.excluded_checks.update(TRADE_GIFT_LOCATIONS)
    window.excluded_checks.difference_update(BOSS_LOCATIONS)
    window.excluded_checks.difference_update(MISC_LOCATIONS)
    window.excluded_checks.difference_update(HEART_PIECE_LOCATIONS)
    window.excluded_checks.difference_update(BLUE_RUPEES)
    window.updateSeashells()
    window.updateOwls()
    window.excluded_checks.difference_update(LEAF_LOCATIONS)
    window.tab_Changed()


def saveSettings(window):
    settings_dict = {
        'Theme': window.mode,
        'Romfs_Folder': window.ui.lineEdit.text(),
        'Output_Folder': window.ui.lineEdit_2.text(),
        'Seed': window.ui.lineEdit_3.text(),
        'Platform': PLATFORMS[window.ui.platformComboBox.currentIndex()],
        'External_Settings_File': window.ui.lineEdit_4.text()
    }

    ldict = locals() # needed to be able to get the new variable value from exec
    for k,v in BASE_OPTIONS.items():
        if isinstance(v, bool):
            exec(f"v = window.ui.{k}.isChecked()", globals(), ldict)
        elif isinstance(v, int):
            if k.endswith('ComboBox'):
                exec(f"v = window.ui.{k}.currentIndex()", globals(), ldict)
            else:
                exec(f"v = window.ui.{k}.value()", globals(), ldict)
        else:
            exec(f"v = window.{k}", globals(), ldict)
        settings_dict[k] = ldict['v']
    
    settings_dict['Excluded_Locations'] = list(window.excluded_checks)

    with open(SETTINGS_PATH, 'w') as f:
        yaml.dump(settings_dict, f, Dumper=MyDumper, sort_keys=False)


def loadSettings(window):
    all_options = [k for k,v in BASE_OPTIONS.items()]
    all_options.extend(EXTRA_OPTIONS)
    
    for k,v in SETTINGS.items():
        if k not in all_options:
            continue
        try:
            if isinstance(v, bool):
                exec(f"window.ui.{k}.setChecked({v})")
            elif isinstance(v, int):
                if k.endswith('ComboBox'):
                    exec(f"window.ui.{k}.setCurrentIndex({v})")
                else:
                    exec(f"window.ui.{k}.setValue({v})")
        except:
            pass
    
    try:
        if SETTINGS['Theme'].lower() in ['light', 'dark']:
            window.mode = str(SETTINGS['Theme'].lower())
    except (KeyError, AttributeError, TypeError):
        pass
    try:
        if os.path.exists(SETTINGS['Romfs_Folder']):
            window.ui.lineEdit.setText(SETTINGS['Romfs_Folder'])
    except (KeyError, TypeError):
        pass
    try:
        if os.path.exists(SETTINGS['Output_Folder']):
            window.ui.lineEdit_2.setText(SETTINGS['Output_Folder'])
    except (KeyError, TypeError):
        pass
    try:
        if os.path.isfile(SETTINGS['External_Settings_File']):
            window.ui.lineEdit_4.setText(SETTINGS['External_Settings_File'])
    except (KeyError, TypeError):
        pass
    try:
        if SETTINGS['Seed'] != "":
            window.ui.lineEdit_3.setText(SETTINGS['Seed'])
    except (KeyError, TypeError):
        pass
    try:
        window.ui.platformComboBox.setCurrentIndex(PLATFORMS.index(SETTINGS['Platform'].lower().strip()))
    except (KeyError, TypeError, IndexError, ValueError):
        window.ui.platformComboBox.setCurrentIndex(0)
    try:
        for check in SETTINGS['Excluded_Locations']:
            if check in TOTAL_CHECKS:
                window.excluded_checks.add(check)
    except (KeyError, TypeError):
        if not window.ui.chestsCheck.isChecked():
            window.excluded_checks.update(MISCELLANEOUS_CHESTS)
        if not window.ui.fishingCheck.isChecked():
            window.excluded_checks.update(FISHING_REWARDS)
        if not window.ui.rapidsCheck.isChecked():
            window.excluded_checks.update(RAPIDS_REWARDS)
        if not window.ui.dampeCheck.isChecked():
            window.excluded_checks.update(DAMPE_REWARDS)
        if not window.ui.giftsCheck.isChecked():
            window.excluded_checks.update(FREE_GIFT_LOCATIONS)
        if not window.ui.tradeGiftsCheck.isChecked():
            window.excluded_checks.update(TRADE_GIFT_LOCATIONS)
        if not window.ui.bossCheck.isChecked():
            window.excluded_checks.update(BOSS_LOCATIONS)
        if not window.ui.miscellaneousCheck.isChecked():
            window.excluded_checks.update(MISC_LOCATIONS)
        if not window.ui.heartsCheck.isChecked():
            window.excluded_checks.update(HEART_PIECE_LOCATIONS)
        if not window.ui.leavesCheck.isChecked():
            window.excluded_checks.update(LEAF_LOCATIONS)
        # if not window.ui.trendyCheck.isChecked():
        #     window.excluded_checks.update(TRENDY_REWARDS)
        # if not window.ui.shopCheck.isChecked():
        #     window.excluded_checks.update(SHOP_ITEMS)
    try:
        for item in SETTINGS['starting_gear']:
            if item in STARTING_ITEMS:
                if window.starting_gear.count(item) < STARTING_ITEMS.count(item):
                    window.starting_gear.append(item)
    except (KeyError, TypeError):
        window.starting_gear = list() # reset starting gear to default if error
