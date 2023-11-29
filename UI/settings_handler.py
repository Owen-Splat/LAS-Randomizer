from randomizer_data import *
import yaml


class MyDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, indentless)



def applyDefaults(window):
    window.ui.chestsCheck.setChecked(True)
    window.excluded_checks.difference_update(MISCELLANEOUS_CHESTS)
    window.ui.fishingCheck.setChecked(True)
    window.excluded_checks.difference_update(FISHING_REWARDS)
    window.ui.rapidsCheck.setChecked(False)
    window.excluded_checks.update(RAPIDS_REWARDS)
    window.ui.dampeCheck.setChecked(False)
    window.excluded_checks.update(DAMPE_REWARDS)
    # window.ui.trendyCheck.setChecked(False)
    window.excluded_checks.update(TRENDY_REWARDS)
    # window.ui.shopCheck.setChecked(True)
    # window.excluded_checks.difference_update(SHOP_ITEMS)
    window.ui.giftsCheck.setChecked(True)
    window.excluded_checks.difference_update(FREE_GIFT_LOCATIONS)
    window.ui.tradeGiftsCheck.setChecked(False)
    window.excluded_checks.update(TRADE_GIFT_LOCATIONS)
    window.ui.bossCheck.setChecked(True)
    window.excluded_checks.difference_update(BOSS_LOCATIONS)
    window.ui.miscellaneousCheck.setChecked(True)
    window.excluded_checks.difference_update(MISC_LOCATIONS)
    window.ui.heartsCheck.setChecked(True)
    window.excluded_checks.difference_update(HEART_PIECE_LOCATIONS)
    window.ui.rupCheck.setChecked(False)
    window.excluded_checks.difference_update(BLUE_RUPEES)
    window.ui.instrumentCheck.setChecked(True)
    window.ui.instrumentsComboBox.setCurrentIndex(0)
    window.ui.seashellsComboBox.setCurrentIndex(2)
    window.updateSeashells()
    window.ui.owlsComboBox.setCurrentIndex(0)
    window.updateOwls()
    window.ui.trapsComboBox.setCurrentIndex(0)
    window.ui.leavesCheck.setChecked(True)
    window.excluded_checks.difference_update(LEAF_LOCATIONS)
    window.ui.tricksComboBox.setCurrentIndex(0)
    window.ui.bookCheck.setChecked(True)
    window.ui.unlockedBombsCheck.setChecked(True)
    window.ui.shuffledBombsCheck.setChecked(False)
    window.ui.fastTrendyCheck.setChecked(False)
    window.ui.stealingCheck.setChecked(True)
    window.ui.farmingCheck.setChecked(True)
    window.ui.shuffledPowderCheck.setChecked(False)
    window.ui.musicCheck.setChecked(False)
    window.ui.enemyCheck.setChecked(False)
    window.ui.spoilerCheck.setChecked(True)
    window.ui.kanaletCheck.setChecked(True)
    window.ui.badPetsCheck.setChecked(False)
    window.ui.bridgeCheck.setChecked(True)
    window.ui.mazeCheck.setChecked(True)
    window.ui.swampCheck.setChecked(False)
    window.ui.stalfosCheck.setChecked(False)
    window.ui.chestSizesCheck.setChecked(False)
    window.ui.songsCheck.setChecked(False)
    window.ui.fastFishingCheck.setChecked(True)
    window.ui.dungeonsCheck.setChecked(False)
    window.ui.ohkoCheck.setChecked(False)
    window.ui.lv1BeamCheck.setChecked(False)
    window.ui.niceRodCheck.setChecked(False)
    window.starting_gear = list()
    window.ui.rupeesSpinBox.setValue(0)
    window.ui.externalSettingsCheck.setChecked(False)
    window.tab_Changed()



def saveSettings(window):
    settings_dict = {
        'Theme': window.mode,
        'Romfs_Folder': window.ui.lineEdit.text(),
        'Output_Folder': window.ui.lineEdit_2.text(),
        "Use_External_Settings": window.ui.externalSettingsCheck.isChecked(),
        'External_Settings_File': window.ui.lineEdit_4.text(),
        'Seed': window.ui.lineEdit_3.text(),
        'Logic': LOGIC_PRESETS[window.ui.tricksComboBox.currentIndex()],
        'Platform': PLATFORMS[window.ui.platformComboBox.currentIndex()],
        'Create_Spoiler': window.ui.spoilerCheck.isChecked(),
        'NonDungeon_Chests': window.ui.chestsCheck.isChecked(),
        'Fishing': window.ui.fishingCheck.isChecked(),
        'Rapids': window.ui.rapidsCheck.isChecked(),
        'Dampe': window.ui.dampeCheck.isChecked(),
        # 'Trendy': window.ui.trendyCheck.isChecked(),
        # 'Shop': window.ui.shopCheck.isChecked(),
        'Free_Gifts': window.ui.giftsCheck.isChecked(),
        'Trade_Quest': window.ui.tradeGiftsCheck.isChecked(),
        'Boss_Drops': window.ui.bossCheck.isChecked(),
        'Miscellaneous': window.ui.miscellaneousCheck.isChecked(),
        'Heart_Pieces': window.ui.heartsCheck.isChecked(),
        'Golden_Leaves': window.ui.leavesCheck.isChecked(),
        'Instruments': window.ui.instrumentCheck.isChecked(),
        'Starting_Instruments': window.ui.instrumentsComboBox.currentIndex(),
        'Seashells': SEASHELL_VALUES[window.ui.seashellsComboBox.currentIndex()],
        'Free_Book': window.ui.bookCheck.isChecked(),
        'Unlocked_Bombs': window.ui.unlockedBombsCheck.isChecked(),
        'Shuffled_Bombs': window.ui.shuffledBombsCheck.isChecked(),
        'Bad_Pets': window.ui.badPetsCheck.isChecked(),
        'Fast_Fishing': window.ui.fastFishingCheck.isChecked(),
        'Fast_Stealing': window.ui.stealingCheck.isChecked(),
        'Fast_Trendy': window.ui.fastTrendyCheck.isChecked(),
        'Fast_Songs': window.ui.songsCheck.isChecked(),
        'Fast_Stalfos': window.ui.stalfosCheck.isChecked(),
        'Scaled_Chest_Sizes': window.ui.chestSizesCheck.isChecked(),
        'Reduced_Farming': window.ui.farmingCheck.isChecked(),
        'Shuffled_Powder': window.ui.shuffledPowderCheck.isChecked(),
        'Open_Kanalet': window.ui.kanaletCheck.isChecked(),
        'Open_Bridge': window.ui.bridgeCheck.isChecked(),
        'Open_Mamu': window.ui.mazeCheck.isChecked(),
        'Traps': TRAP_SETTINGS[window.ui.trapsComboBox.currentIndex()],
        'Blupsanity': window.ui.rupCheck.isChecked(),
        'Classic_D2': window.ui.swampCheck.isChecked(),
        'Owl_Statues': OWLS_SETTINGS[window.ui.owlsComboBox.currentIndex()],
        # 'Shuffled_Companions': window.ui.companionCheck.isChecked(),
        # 'Randomize_Entrances': window.ui.loadingCheck.isChecked(),
        'Randomize_Music': window.ui.musicCheck.isChecked(),
        'Randomize_Enemies': window.ui.enemyCheck.isChecked(),
        'Shuffled_Dungeons': window.ui.dungeonsCheck.isChecked(),
        '1HKO': window.ui.ohkoCheck.isChecked(),
        'Lv1_Beam': window.ui.lv1BeamCheck.isChecked(),
        'Nice_Rod': window.ui.niceRodCheck.isChecked(),
        'Starting_Items': window.starting_gear,
        'Starting_Rupees': window.ui.rupeesSpinBox.value(),
        'Excluded_Locations': list(window.excluded_checks)
    }
    
    with open(SETTINGS_PATH, 'w') as f:
        yaml.dump(settings_dict, f, Dumper=MyDumper, sort_keys=False)



def loadSettings(window):
    try:
        if SETTINGS['Theme'].lower() in ['light', 'dark']:
            window.mode = str(SETTINGS['Theme'].lower())
        else:
            window.mode = str('light')
    except (KeyError, AttributeError, TypeError):
        window.mode = str('light')
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
        window.ui.externalSettingsCheck.setChecked(SETTINGS['Use_External_Settings'])
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
        window.ui.chestsCheck.setChecked(SETTINGS['NonDungeon_Chests'])
    except (KeyError, TypeError):
        window.ui.chestsCheck.setChecked(True)
    try:
        window.ui.fishingCheck.setChecked(SETTINGS['Fishing'])
    except (KeyError, TypeError):
        window.ui.fishingCheck.setChecked(True)
    try:
        window.ui.fastFishingCheck.setChecked(SETTINGS['Fast_Fishing'])
    except (KeyError, TypeError):
        window.ui.fastFishingCheck.setChecked(True)
    try:
        window.ui.rapidsCheck.setChecked(SETTINGS['Rapids'])
    except (KeyError, TypeError):
        window.ui.rapidsCheck.setChecked(False)
    try:
        window.ui.dampeCheck.setChecked(SETTINGS['Dampe'])
    except (KeyError, TypeError):
        window.ui.dampeCheck.setChecked(False)
    # try:
    #     window.ui.trendyCheck.setChecked(SETTINGS['Trendy'])
    # except (KeyError, TypeError):
    #     window.ui.trendyCheck.setChecked(True)
    # try:
    #     window.ui.shopCheck.setChecked(SETTINGS['Shop'])
    # except (KeyError, TypeError):
    #     window.ui.shopCheck.setChecked(True)
    try:
        window.ui.giftsCheck.setChecked(SETTINGS['Free_Gifts'])
    except (KeyError, TypeError):
        window.ui.giftsCheck.setChecked(True)
    try:
        window.ui.tradeGiftsCheck.setChecked(SETTINGS['Trade_Quest'])
    except (KeyError, TypeError):
        window.ui.tradeGiftsCheck.setChecked(False)
    try:
        window.ui.bossCheck.setChecked(SETTINGS['Boss_Drops'])
    except (KeyError, TypeError):
        window.ui.bossCheck.setChecked(True)
    try:
        window.ui.miscellaneousCheck.setChecked(SETTINGS['Miscellaneous'])
    except (KeyError, TypeError):
        window.ui.miscellaneousCheck.setChecked(True)
    try:
        window.ui.heartsCheck.setChecked(SETTINGS['Heart_Pieces'])
    except (KeyError, TypeError):
        window.ui.heartsCheck.setChecked(True)
    try:
        window.ui.instrumentCheck.setChecked(SETTINGS['Instruments'])
    except (KeyError, TypeError):
        window.ui.instrumentCheck.setChecked(True)
    try:
        window.ui.leavesCheck.setChecked(SETTINGS['Golden_Leaves'])
    except (KeyError, TypeError):
        window.ui.leavesCheck.setChecked(True)
    try:
        window.ui.instrumentsComboBox.setCurrentIndex(SETTINGS['Starting_Instruments'])
    except (KeyError, TypeError):
        window.ui.instrumentsComboBox.setCurrentIndex(0)
    try:
        window.ui.seashellsComboBox.setCurrentIndex(SEASHELL_VALUES.index(SETTINGS['Seashells']))
    except (KeyError, TypeError, IndexError):
        window.ui.seashellsComboBox.setCurrentIndex(2)
    try:
        window.ui.tricksComboBox.setCurrentIndex(LOGIC_PRESETS.index(SETTINGS['Logic'].lower().strip()))
    except (KeyError, TypeError, IndexError):
        window.ui.tricksComboBox.setCurrentIndex(0)
    try:
        window.ui.bookCheck.setChecked(SETTINGS['Free_Book'])
    except (KeyError, TypeError):
        window.ui.bookCheck.setChecked(True)
    try:
        window.ui.unlockedBombsCheck.setChecked(SETTINGS['Unlocked_Bombs'])
    except (KeyError, TypeError):
        window.ui.unlockedBombsCheck.setChecked(True)
    try:
        window.ui.fastTrendyCheck.setChecked(SETTINGS['Fast_Trendy'])
    except (KeyError, TypeError):
        window.ui.fastTrendyCheck.setChecked(False)
    try:
        window.ui.shuffledBombsCheck.setChecked(SETTINGS['Shuffled_Bombs'])
    except (KeyError, TypeError):
        window.ui.shuffledBombsCheck.setChecked(False)
    try:
        window.ui.stealingCheck.setChecked(SETTINGS['Fast_Stealing'])
    except (KeyError, TypeError):
        window.ui.stealingCheck.setChecked(True)
    try:
        window.ui.songsCheck.setChecked(SETTINGS['Fast_Songs'])
    except (KeyError, TypeError):
        window.ui.songsCheck.setChecked(False)
    try:
        window.ui.stalfosCheck.setChecked(SETTINGS['Fast_Stalfos'])
    except (KeyError, TypeError):
        window.ui.stalfosCheck.setChecked(False)
    try:
        window.ui.chestSizesCheck.setChecked(SETTINGS['Scaled_Chest_Sizes'])
    except (KeyError, TypeError):
        window.ui.chestSizesCheck.setChecked(False)
    try:
        window.ui.farmingCheck.setChecked(SETTINGS['Reduced_Farming'])
    except (KeyError, TypeError):
        window.ui.farmingCheck.setChecked(True)
    try:
        window.ui.shuffledPowderCheck.setChecked(SETTINGS['Shuffled_Powder'])
    except (KeyError, TypeError):
        window.ui.shuffledPowderCheck.setChecked(False)
    try:
        window.ui.kanaletCheck.setChecked(SETTINGS['Open_Kanalet'])
    except (KeyError, TypeError):
        window.ui.kanaletCheck.setChecked(True)
    try:
        window.ui.bridgeCheck.setChecked(SETTINGS['Open_Bridge'])
    except (KeyError, TypeError):
        window.ui.bridgeCheck.setChecked(True)
    try:
        window.ui.mazeCheck.setChecked(SETTINGS['Open_Mamu'])
    except (KeyError, TypeError):
        window.ui.mazeCheck.setChecked(True)
    try:
        window.ui.badPetsCheck.setChecked(SETTINGS['Bad_Pets'])
    except (KeyError, TypeError):
        window.ui.badPetsCheck.setChecked(False)
    try:
        window.ui.trapsComboBox.setCurrentIndex(TRAP_SETTINGS.index(SETTINGS['Traps'].lower().strip()))
    except (KeyError, TypeError, IndexError, ValueError):
        window.ui.trapsComboBox.setCurrentIndex(0)
    try:
        window.ui.rupCheck.setChecked(SETTINGS['Blupsanity'])
    except(KeyError, TypeError):
        window.ui.rupCheck.setChecked(False)
    try:
        window.ui.swampCheck.setChecked(SETTINGS['Classic_D2'])
    except (KeyError, TypeError):
        window.ui.swampCheck.setChecked(False)
    try:
        window.ui.owlsComboBox.setCurrentIndex(OWLS_SETTINGS.index(SETTINGS['Owl_Statues'].lower().strip()))
    except (KeyError, TypeError, IndexError, ValueError):
        window.ui.owlsComboBox.setCurrentIndex(0)
    # try:
    #     window.ui.companionCheck.setChecked(SETTINGS['Shuffled_Companions'])
    # except (KeyError, TypeError):
    #     window.ui.companionCheck.setChecked(True)
    # try:
    #     window.ui.loadingCheck.setChecked(SETTINGS['Randomize_Entrances'])
    # except (KeyError, TypeError):
    #     window.ui.loadingCheck.setChecked(False)
    try:
        window.ui.musicCheck.setChecked(SETTINGS['Randomize_Music'])
    except (KeyError, TypeError):
        window.ui.musicCheck.setChecked(False)
    try:
        window.ui.enemyCheck.setChecked(SETTINGS['Randomize_Enemies'])
    except (KeyError, TypeError):
        window.ui.enemyCheck.setChecked(False)
    try:
        window.ui.dungeonsCheck.setChecked(SETTINGS['Shuffled_Dungeons'])
    except (KeyError, TypeError):
        window.ui.dungeonsCheck.setChecked(False)
    try:
        window.ui.spoilerCheck.setChecked(SETTINGS['Create_Spoiler'])
    except (KeyError, TypeError):
        window.ui.spoilerCheck.setChecked(True)
    try:
        window.ui.platformComboBox.setCurrentIndex(PLATFORMS.index(SETTINGS['Platform'].lower().strip()))
    except (KeyError, TypeError, IndexError, ValueError):
        window.ui.platformComboBox.setCurrentIndex(0)
    try:
        window.ui.ohkoCheck.setChecked(SETTINGS['1HKO'])
    except (KeyError, TypeError):
        window.ui.ohkoCheck.setChecked(False)
    try:
        window.ui.lv1BeamCheck.setChecked(SETTINGS['Lv1_Beam'])
    except (KeyError, TypeError):
        window.ui.lv1BeamCheck.setChecked(False)
    try:
        window.ui.niceRodCheck.setChecked(SETTINGS['Nice_Rod'])
    except (KeyError, TypeError):
        window.ui.niceRodCheck.setChecked(False)
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
        for item in SETTINGS['Starting_Items']:
            if item in STARTING_ITEMS:
                if window.starting_gear.count(item) < STARTING_ITEMS.count(item):
                    window.starting_gear.append(item)
    except (KeyError, TypeError):
        window.starting_gear = list() # reset starting gear to default if error
    try:
        window.ui.rupeesSpinBox.setValue(SETTINGS['Starting_Rupees'])
    except (KeyError, TypeError):
        window.ui.rupeesSpinBox.setValue(0)
