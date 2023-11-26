from PySide6 import QtCore, QtWidgets
from UI.ui_form import Ui_MainWindow
from UI.progress_window import ProgressWindow
from update import UpdateProcess, LogicUpdateProcess
from randomizer_paths import IS_RUNNING_FROM_SOURCE
from randomizer_data import *

import os
import yaml
import random
from re import sub



class MainWindow(QtWidgets.QMainWindow):
    
    def __init__(self):
        super (MainWindow, self).__init__()
        # self.trans = QtCore.QTranslator(self)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.includeButton_2.setVisible(False)
        self.ui.excludeButton_2.setVisible(False)
        # self.options = ([('English', ''), ('Français', 'eng-fr' ), ('中文', 'eng-chs'), ])

        # Keep track of stuff
        self.mode = str('light')
        self.logic_version = LOGIC_VERSION
        self.logic_defs = LOGIC_RAW
        self.excluded_checks = set()
        self.starting_gear = list()
        self.overworld_owls = bool(False)
        self.dungeon_owls = bool(False)

        # Load User Settings
        if not DEFAULTS:
            self.loadSettings()
        else:
            self.applyDefaults()
                
        self.updateOwls()
        self.updateSeashells()
        
        if self.mode == 'light':
            self.setStyleSheet(LIGHT_STYLESHEET)
            self.ui.explainationLabel.setStyleSheet('color: rgb(80, 80, 80);')
        else:
            self.setStyleSheet(DARK_STYLESHEET)
            self.ui.explainationLabel.setStyleSheet('color: rgb(175, 175, 175);')
        
        ### SUBSCRIBE TO EVENTS
        
        # menu bar items
        self.ui.actionLight.triggered.connect(self.setLightMode)
        self.ui.actionDark.triggered.connect(self.setDarkMode)
        self.ui.actionChangelog.triggered.connect(self.showChangelog)
        self.ui.actionKnown_Issues.triggered.connect(self.showIssues)
        self.ui.actionHelp.triggered.connect(self.showInfo)
        # folder browsing, seed generation, and randomize button
        self.ui.browseButton1.clicked.connect(self.romBrowse)
        self.ui.browseButton2.clicked.connect(self.outBrowse)
        self.ui.browseButton3.clicked.connect(self.settingsBrowse)
        self.ui.seedButton.clicked.connect(self.generateSeed)
        self.ui.randomizeButton.clicked.connect(self.randomizeButton_Clicked)
        self.ui.resetButton.clicked.connect(self.applyDefaults)
        # progress checks
        self.ui.chestsCheck.clicked.connect(self.chestsCheck_Clicked)
        self.ui.fishingCheck.clicked.connect(self.fishingCheck_Clicked)
        self.ui.rapidsCheck.clicked.connect(self.rapidsCheck_Clicked)
        self.ui.dampeCheck.clicked.connect(self.dampeCheck_Clicked)
        # self.ui.trendyCheck.clicked.connect(self.trendyCheck_Clicked)
        # self.ui.shopCheck.clicked.connect(self.shopCheck_Clicked)
        self.ui.giftsCheck.clicked.connect(self.giftsCheck_Clicked)
        self.ui.tradeGiftsCheck.clicked.connect(self.tradeQuest_Clicked)
        self.ui.bossCheck.clicked.connect(self.bossCheck_Clicked)
        self.ui.miscellaneousCheck.clicked.connect(self.miscellaneousCheck_Clicked)
        self.ui.heartsCheck.clicked.connect(self.heartsCheck_Clicked)
        self.ui.rupCheck.clicked.connect(self.rupCheck_Clicked)
        self.ui.seashellsComboBox.currentIndexChanged.connect(self.updateSeashells)
        self.ui.leavesCheck.clicked.connect(self.leavesCheck_Clicked)
        self.ui.owlsComboBox.currentIndexChanged.connect(self.updateOwls)
        # tabs
        self.ui.tabWidget.currentChanged.connect(self.tab_Changed)
        self.ui.includeButton.clicked.connect(self.includeButton_Clicked)
        self.ui.excludeButton.clicked.connect(self.excludeButton_Clicked)
        self.ui.includeButton_3.clicked.connect(self.includeButton_3_Clicked)
        self.ui.excludeButton_3.clicked.connect(self.excludeButton_3_Clicked)
        # self.ui.includeButton_2.clicked.connect(self.includeButton_2_Clicked)
        # self.ui.excludeButton_2.clicked.connect(self.excludeButton_2_Clicked)
        ### DESCRIPTIONS
        desc_items = self.ui.tab.findChildren(QtWidgets.QCheckBox)
        desc_items.extend([
            self.ui.seashellsComboBox,
            self.ui.tricksComboBox,
            self.ui.instrumentsComboBox,
            self.ui.owlsComboBox,
            self.ui.platformComboBox,
            self.ui.rupeesSpinBox,
            self.ui.trapsComboBox
        ])
        for item in desc_items:
            item.installEventFilter(self)
        
        self.makeSmartComboBoxes()

        ### show and check for updates
        self.setFixedSize(780, 650)
        self.setWindowTitle(f'{self.windowTitle()} v{VERSION}')
        
        # self.ui.retranslateUi(self)
        
        self.process = UpdateProcess()
        self.process.can_update.connect(self.showUpdate)
        self.process.give_version.connect(self.obtainVersion)
        self.process.start()
        
        self.show()


    def makeSmartComboBoxes(self):
        combos = [
            self.ui.seashellsComboBox,
            self.ui.tricksComboBox,
            self.ui.instrumentsComboBox,
            self.ui.owlsComboBox,
            self.ui.platformComboBox,
            self.ui.trapsComboBox
        ]
        for combo in combos:
            combo.__class__ = SmartComboBox
            combo.popup_closed.connect(self.closeComboBox)
    

    def closeComboBox(self):
        self.ui.explainationLabel.setText('Hover over an option to see what it does')
        if self.mode == 'light':
            self.ui.explainationLabel.setStyleSheet('color: rgb(80, 80, 80);')
        else:
            self.ui.explainationLabel.setStyleSheet('color: rgb(175, 175, 175);')
    

    def eventFilter(self, source, event):

        if event.type() == QtCore.QEvent.Type.HoverEnter:
            self.ui.explainationLabel.setText(source.whatsThis())
            if self.mode == 'light':
                self.ui.explainationLabel.setStyleSheet('color: black;')
            else:
                self.ui.explainationLabel.setStyleSheet('color: white;')
        
        elif event.type() == QtCore.QEvent.Type.HoverLeave:
            self.ui.explainationLabel.setText('Hover over an option to see what it does')
            if self.mode == 'light':
                self.ui.explainationLabel.setStyleSheet('color: rgb(80, 80, 80);')
            else:
                self.ui.explainationLabel.setStyleSheet('color: rgb(175, 175, 175);')
        
        return QtWidgets.QWidget.eventFilter(self, source, event)
    

    def obtainVersion(self, version):
        self.new_version = version
    

    def showUpdate(self, update):
        if not update:
            self.checkLogic()
            return
        
        update_menu = self.ui.menuBar.addMenu('NEW VERSION AVAILABLE!')
        update_action = update_menu.addAction('Update')
        update_action.triggered.connect(self.updateClicked)
        self.updateClicked()
    

    def updateClicked(self):
        message = QtWidgets.QMessageBox()
        message.setWindowTitle("Link's Awakening Switch Randomizer Update")
        message.setText(f"""
        Current version: {VERSION}<br></br>
        <br></br>

        New version: {self.new_version}<br></br>
        <br></br>

        <a href="{DOWNLOAD_PAGE}" style="color: rgb(31, 81, 255);">{DOWNLOAD_PAGE}</a>
        """)

        if self.mode == 'light':
            message.setStyleSheet(LIGHT_STYLESHEET)
        else:
            message.setStyleSheet(DARK_STYLESHEET)
        
        message.exec()
    
    
    def checkLogic(self):
        self.logic_process = LogicUpdateProcess(ver=self.logic_version)
        self.logic_process.can_update.connect(self.showLogicUpdate)
        self.logic_process.give_logic.connect(self.obtainLogic)
        self.logic_process.start()
        self.logic_process.exec()
    

    def obtainLogic(self, version_and_logic):
        self.logic_version = version_and_logic[0]
        self.logic_defs = version_and_logic[1]
        with open(LOGIC_PATH, 'w+') as f:
            f.write(f'# {self.logic_version}\n')
            f.write(self.logic_defs)


    def showLogicUpdate(self, update):
        if not update:
            return
        
        message = QtWidgets.QMessageBox()
        message.setWindowTitle("Logic Updater")
        
        if self.mode == 'light':
            message.setStyleSheet(LIGHT_STYLESHEET)
        else:
            message.setStyleSheet(DARK_STYLESHEET)
        
        message.setText('Logic has been updated')
        message.exec()


    # apply defaults
    def applyDefaults(self):
        self.ui.chestsCheck.setChecked(True)
        self.excluded_checks.difference_update(MISCELLANEOUS_CHESTS)

        self.ui.fishingCheck.setChecked(True)
        self.excluded_checks.difference_update(FISHING_REWARDS)

        self.ui.rapidsCheck.setChecked(False)
        self.excluded_checks.update(RAPIDS_REWARDS)

        self.ui.dampeCheck.setChecked(False)
        self.excluded_checks.update(DAMPE_REWARDS)

        # self.ui.trendyCheck.setChecked(False)
        self.excluded_checks.update(TRENDY_REWARDS)

        # self.ui.shopCheck.setChecked(True)
        # self.excluded_checks.difference_update(SHOP_ITEMS)

        self.ui.giftsCheck.setChecked(True)
        self.excluded_checks.difference_update(FREE_GIFT_LOCATIONS)

        self.ui.tradeGiftsCheck.setChecked(False)
        self.excluded_checks.update(TRADE_GIFT_LOCATIONS)

        self.ui.bossCheck.setChecked(True)
        self.excluded_checks.difference_update(BOSS_LOCATIONS)

        self.ui.miscellaneousCheck.setChecked(True)
        self.excluded_checks.difference_update(MISC_LOCATIONS)

        self.ui.heartsCheck.setChecked(True)
        self.excluded_checks.difference_update(HEART_PIECE_LOCATIONS)

        self.ui.rupCheck.setChecked(False)
        self.excluded_checks.difference_update(BLUE_RUPEES)

        self.ui.instrumentCheck.setChecked(True)
        self.ui.instrumentsComboBox.setCurrentIndex(0)

        self.ui.seashellsComboBox.setCurrentIndex(2)
        self.updateSeashells()

        self.ui.owlsComboBox.setCurrentIndex(0)
        self.updateOwls()

        self.ui.trapsComboBox.setCurrentIndex(0)

        self.ui.leavesCheck.setChecked(True)
        self.excluded_checks.difference_update(LEAF_LOCATIONS)

        self.ui.tricksComboBox.setCurrentIndex(0)

        self.ui.bookCheck.setChecked(True)
        self.ui.unlockedBombsCheck.setChecked(True)
        self.ui.shuffledBombsCheck.setChecked(False)
        self.ui.fastTrendyCheck.setChecked(False)
        self.ui.stealingCheck.setChecked(True)
        self.ui.farmingCheck.setChecked(True)
        self.ui.shuffledPowderCheck.setChecked(False)
        self.ui.musicCheck.setChecked(False)
        self.ui.enemyCheck.setChecked(False)
        self.ui.spoilerCheck.setChecked(True)
        self.ui.kanaletCheck.setChecked(True)
        self.ui.badPetsCheck.setChecked(False)
        self.ui.bridgeCheck.setChecked(True)
        self.ui.mazeCheck.setChecked(True)
        self.ui.swampCheck.setChecked(False)
        self.ui.stalfosCheck.setChecked(False)
        self.ui.chestSizesCheck.setChecked(False)
        self.ui.songsCheck.setChecked(False)
        self.ui.fastFishingCheck.setChecked(True)
        self.ui.dungeonsCheck.setChecked(False)

        self.ui.ohkoCheck.setChecked(False)
        self.ui.lv1BeamCheck.setChecked(False)
        self.ui.niceRodCheck.setChecked(False)

        self.starting_gear = list() # fully reset starting items
        self.ui.rupeesSpinBox.setValue(0)

        self.ui.externalSettingsCheck.setChecked(False)

        self.tab_Changed() # just call the same event as when changing the tab to refresh the list


    def saveSettings(self):
        settings_dict = {
            'Theme': self.mode,
            'Romfs_Folder': self.ui.lineEdit.text(),
            'Output_Folder': self.ui.lineEdit_2.text(),
            "Use_External_Settings": self.ui.externalSettingsCheck.isChecked(),
            'External_Settings_File': self.ui.lineEdit_4.text(),
            'Seed': self.ui.lineEdit_3.text(),
            'Logic': LOGIC_PRESETS[self.ui.tricksComboBox.currentIndex()],
            'Platform': PLATFORMS[self.ui.platformComboBox.currentIndex()],
            'Create_Spoiler': self.ui.spoilerCheck.isChecked(),
            'NonDungeon_Chests': self.ui.chestsCheck.isChecked(),
            'Fishing': self.ui.fishingCheck.isChecked(),
            'Rapids': self.ui.rapidsCheck.isChecked(),
            'Dampe': self.ui.dampeCheck.isChecked(),
            # 'Trendy': self.ui.trendyCheck.isChecked(),
            # 'Shop': self.ui.shopCheck.isChecked(),
            'Free_Gifts': self.ui.giftsCheck.isChecked(),
            'Trade_Quest': self.ui.tradeGiftsCheck.isChecked(),
            'Boss_Drops': self.ui.bossCheck.isChecked(),
            'Miscellaneous': self.ui.miscellaneousCheck.isChecked(),
            'Heart_Pieces': self.ui.heartsCheck.isChecked(),
            'Golden_Leaves': self.ui.leavesCheck.isChecked(),
            'Instruments': self.ui.instrumentCheck.isChecked(),
            'Starting_Instruments': self.ui.instrumentsComboBox.currentIndex(),
            'Seashells': SEASHELL_VALUES[self.ui.seashellsComboBox.currentIndex()],
            'Free_Book': self.ui.bookCheck.isChecked(),
            'Unlocked_Bombs': self.ui.unlockedBombsCheck.isChecked(),
            'Shuffled_Bombs': self.ui.shuffledBombsCheck.isChecked(),
            'Bad_Pets': self.ui.badPetsCheck.isChecked(),
            'Fast_Fishing': self.ui.fastFishingCheck.isChecked(),
            'Fast_Stealing': self.ui.stealingCheck.isChecked(),
            'Fast_Trendy': self.ui.fastTrendyCheck.isChecked(),
            'Fast_Songs': self.ui.songsCheck.isChecked(),
            'Fast_Stalfos': self.ui.stalfosCheck.isChecked(),
            'Scaled_Chest_Sizes': self.ui.chestSizesCheck.isChecked(),
            'Reduced_Farming': self.ui.farmingCheck.isChecked(),
            'Shuffled_Powder': self.ui.shuffledPowderCheck.isChecked(),
            'Open_Kanalet': self.ui.kanaletCheck.isChecked(),
            'Open_Bridge': self.ui.bridgeCheck.isChecked(),
            'Open_Mamu': self.ui.mazeCheck.isChecked(),
            'Traps': TRAP_SETTINGS[self.ui.trapsComboBox.currentIndex()],
            'Blupsanity': self.ui.rupCheck.isChecked(),
            'Classic_D2': self.ui.swampCheck.isChecked(),
            'Owl_Statues': OWLS_SETTINGS[self.ui.owlsComboBox.currentIndex()],
            # 'Shuffled_Companions': self.ui.companionCheck.isChecked(),
            # 'Randomize_Entrances': self.ui.loadingCheck.isChecked(),
            'Randomize_Music': self.ui.musicCheck.isChecked(),
            'Randomize_Enemies': self.ui.enemyCheck.isChecked(),
            'Shuffled_Dungeons': self.ui.dungeonsCheck.isChecked(),
            '1HKO': self.ui.ohkoCheck.isChecked(),
            'Lv1_Beam': self.ui.lv1BeamCheck.isChecked(),
            'Nice_Rod': self.ui.niceRodCheck.isChecked(),
            'Starting_Items': self.starting_gear,
            'Starting_Rupees': self.ui.rupeesSpinBox.value(),
            'Excluded_Locations': list(self.excluded_checks)
        }
        
        with open(SETTINGS_PATH, 'w') as settingsFile:
            yaml.dump(settings_dict, settingsFile, Dumper=MyDumper, sort_keys=False)


    def loadSettings(self):
        
        # theme
        try:
            if SETTINGS['Theme'].lower() in ['light', 'dark']:
                self.mode = str(SETTINGS['Theme'].lower())
            else:
                self.mode = str('light')
        except (KeyError, AttributeError, TypeError):
            self.mode = str('light')

        # romfs folder
        try:
            if os.path.exists(SETTINGS['Romfs_Folder']):
                self.ui.lineEdit.setText(SETTINGS['Romfs_Folder'])
        except (KeyError, TypeError):
            pass
        
        # output folder
        try:
            if os.path.exists(SETTINGS['Output_Folder']):
                self.ui.lineEdit_2.setText(SETTINGS['Output_Folder'])
        except (KeyError, TypeError):
            pass
        
        # use external settings
        try:
            self.ui.externalSettingsCheck.setChecked(SETTINGS['Use_External_Settings'])
        except (KeyError, TypeError):
            pass

        # external settings file
        try:
            if os.path.isfile(SETTINGS['External_Settings_File']):
                self.ui.lineEdit_4.setText(SETTINGS['External_Settings_File'])
        except (KeyError, TypeError):
            pass
        
        # seed
        try:
            if SETTINGS['Seed'] != "":
                self.ui.lineEdit_3.setText(SETTINGS['Seed'])
        except (KeyError, TypeError):
            pass
        
        # nondungeon chests
        try:
            self.ui.chestsCheck.setChecked(SETTINGS['NonDungeon_Chests'])
        except (KeyError, TypeError):
            self.ui.chestsCheck.setChecked(True)
        
        # fishing
        try:
            self.ui.fishingCheck.setChecked(SETTINGS['Fishing'])
        except (KeyError, TypeError):
            self.ui.fishingCheck.setChecked(True)
        
        # fast fishing
        try:
            self.ui.fastFishingCheck.setChecked(SETTINGS['Fast_Fishing'])
        except (KeyError, TypeError):
            self.ui.fastFishingCheck.setChecked(True)
        
        # rapids
        try:
            self.ui.rapidsCheck.setChecked(SETTINGS['Rapids'])
        except (KeyError, TypeError):
            self.ui.rapidsCheck.setChecked(False)
        
        # dampe
        try:
            self.ui.dampeCheck.setChecked(SETTINGS['Dampe'])
        except (KeyError, TypeError):
            self.ui.dampeCheck.setChecked(False)
        
        # # trendy
        # try:
        #     self.ui.trendyCheck.setChecked(SETTINGS['Trendy'])
        # except (KeyError, TypeError):
        #     self.ui.trendyCheck.setChecked(True)
        
        # # shop
        # try:
        #     self.ui.shopCheck.setChecked(SETTINGS['Shop'])
        # except (KeyError, TypeError):
        #     self.ui.shopCheck.setChecked(True)
        
        # free gifts
        try:
            self.ui.giftsCheck.setChecked(SETTINGS['Free_Gifts'])
        except (KeyError, TypeError):
            self.ui.giftsCheck.setChecked(True)
        
        # trade gifts
        try:
            self.ui.tradeGiftsCheck.setChecked(SETTINGS['Trade_Quest'])
        except (KeyError, TypeError):
            self.ui.tradeGiftsCheck.setChecked(False)
        
        # boss drops
        try:
            self.ui.bossCheck.setChecked(SETTINGS['Boss_Drops'])
        except (KeyError, TypeError):
            self.ui.bossCheck.setChecked(True)
        
        # misc items
        try:
            self.ui.miscellaneousCheck.setChecked(SETTINGS['Miscellaneous'])
        except (KeyError, TypeError):
            self.ui.miscellaneousCheck.setChecked(True)
        
        # heart pieces
        try:
            self.ui.heartsCheck.setChecked(SETTINGS['Heart_Pieces'])
        except (KeyError, TypeError):
            self.ui.heartsCheck.setChecked(True)
        
        # instruments
        try:
            self.ui.instrumentCheck.setChecked(SETTINGS['Instruments'])
        except (KeyError, TypeError):
            self.ui.instrumentCheck.setChecked(True)
        
        # golden leaves
        try:
            self.ui.leavesCheck.setChecked(SETTINGS['Golden_Leaves'])
        except (KeyError, TypeError):
            self.ui.leavesCheck.setChecked(True)

        # starting instruments
        try:
            self.ui.instrumentsComboBox.setCurrentIndex(SETTINGS['Starting_Instruments'])
        except (KeyError, TypeError):
            self.ui.instrumentsComboBox.setCurrentIndex(0)

        # seashells
        try:
            self.ui.seashellsComboBox.setCurrentIndex(SEASHELL_VALUES.index(SETTINGS['Seashells']))
        except (KeyError, TypeError, IndexError):
            self.ui.seashellsComboBox.setCurrentIndex(2)
        
        # logic
        try:
            self.ui.tricksComboBox.setCurrentIndex(LOGIC_PRESETS.index(SETTINGS['Logic'].lower().strip()))
        except (KeyError, TypeError, IndexError):
            self.ui.tricksComboBox.setCurrentIndex(0)
        
        # free book
        try:
            self.ui.bookCheck.setChecked(SETTINGS['Free_Book'])
        except (KeyError, TypeError):
            self.ui.bookCheck.setChecked(True)
        
        # unlocked bombs
        try:
            self.ui.unlockedBombsCheck.setChecked(SETTINGS['Unlocked_Bombs'])
        except (KeyError, TypeError):
            self.ui.unlockedBombsCheck.setChecked(True)
        
        # fast trendy
        try:
            self.ui.fastTrendyCheck.setChecked(SETTINGS['Fast_Trendy'])
        except (KeyError, TypeError):
            self.ui.fastTrendyCheck.setChecked(False)
        
        # shuffled bombs
        try:
            self.ui.shuffledBombsCheck.setChecked(SETTINGS['Shuffled_Bombs'])
        except (KeyError, TypeError):
            self.ui.shuffledBombsCheck.setChecked(False)

        # fast stealing
        try:
            self.ui.stealingCheck.setChecked(SETTINGS['Fast_Stealing'])
        except (KeyError, TypeError):
            self.ui.stealingCheck.setChecked(True)
        
        # fast songs
        try:
            self.ui.songsCheck.setChecked(SETTINGS['Fast_Songs'])
        except (KeyError, TypeError):
            self.ui.songsCheck.setChecked(False)
        
        # fast master stalfos
        try:
            self.ui.stalfosCheck.setChecked(SETTINGS['Fast_Stalfos'])
        except (KeyError, TypeError):
            self.ui.stalfosCheck.setChecked(False)
        
        # scaled chest sizes
        try:
            self.ui.chestSizesCheck.setChecked(SETTINGS['Scaled_Chest_Sizes'])
        except (KeyError, TypeError):
            self.ui.chestSizesCheck.setChecked(False)
        
        # reduced farming
        try:
            self.ui.farmingCheck.setChecked(SETTINGS['Reduced_Farming'])
        except (KeyError, TypeError):
            self.ui.farmingCheck.setChecked(True)
        
        # shuffled powder
        try:
            self.ui.shuffledPowderCheck.setChecked(SETTINGS['Shuffled_Powder'])
        except (KeyError, TypeError):
            self.ui.shuffledPowderCheck.setChecked(False)
        
        # open kanalet
        try:
            self.ui.kanaletCheck.setChecked(SETTINGS['Open_Kanalet'])
        except (KeyError, TypeError):
            self.ui.kanaletCheck.setChecked(True)
        
        # open bridge
        try:
            self.ui.bridgeCheck.setChecked(SETTINGS['Open_Bridge'])
        except (KeyError, TypeError):
            self.ui.bridgeCheck.setChecked(True)
        
        # open mamu
        try:
            self.ui.mazeCheck.setChecked(SETTINGS['Open_Mamu'])
        except (KeyError, TypeError):
            self.ui.mazeCheck.setChecked(True)
        
        # bad pets - companions follow inside dungeons
        try:
            self.ui.badPetsCheck.setChecked(SETTINGS['Bad_Pets'])
        except (KeyError, TypeError):
            self.ui.badPetsCheck.setChecked(False)

        # traps
        try:
            self.ui.trapsComboBox.setCurrentIndex(TRAP_SETTINGS.index(SETTINGS['Traps'].lower().strip()))
        except (KeyError, TypeError, IndexError, ValueError):
            self.ui.trapsComboBox.setCurrentIndex(0)
        
        # color dungeon rupees
        try:
            self.ui.rupCheck.setChecked(SETTINGS['Blupsanity'])
        except(KeyError, TypeError):
            self.ui.rupCheck.setChecked(False)
        
        # classic d2
        try:
            self.ui.swampCheck.setChecked(SETTINGS['Classic_D2'])
        except (KeyError, TypeError):
            self.ui.swampCheck.setChecked(False)
        
        # owl statues
        try:
            self.ui.owlsComboBox.setCurrentIndex(OWLS_SETTINGS.index(SETTINGS['Owl_Statues'].lower().strip()))
        except (KeyError, TypeError, IndexError, ValueError):
            self.ui.owlsComboBox.setCurrentIndex(0)
        
        # # companions
        # try:
        #     self.ui.companionCheck.setChecked(SETTINGS['Shuffled_Companions'])
        # except (KeyError, TypeError):
        #     self.ui.companionCheck.setChecked(True)

        # # randomize entrances
        # try:
        #     self.ui.loadingCheck.setChecked(SETTINGS['Randomize_Entrances'])
        # except (KeyError, TypeError):
        #     self.ui.loadingCheck.setChecked(False)

        # randomize music
        try:
            self.ui.musicCheck.setChecked(SETTINGS['Randomize_Music'])
        except (KeyError, TypeError):
            self.ui.musicCheck.setChecked(False)
        
        # randomize enemies
        try:
            self.ui.enemyCheck.setChecked(SETTINGS['Randomize_Enemies'])
        except (KeyError, TypeError):
            self.ui.enemyCheck.setChecked(False)
        
        # shuffled dungeons
        try:
            self.ui.dungeonsCheck.setChecked(SETTINGS['Shuffled_Dungeons'])
        except (KeyError, TypeError):
            self.ui.dungeonsCheck.setChecked(False)
        
        # spoiler log
        try:
            self.ui.spoilerCheck.setChecked(SETTINGS['Create_Spoiler'])
        except (KeyError, TypeError):
            self.ui.spoilerCheck.setChecked(True)
        
        # platform
        try:
            self.ui.platformComboBox.setCurrentIndex(PLATFORMS.index(SETTINGS['Platform'].lower().strip()))
        except (KeyError, TypeError, IndexError, ValueError):
            self.ui.platformComboBox.setCurrentIndex(0)
        
        # 1HKO
        try:
            self.ui.ohkoCheck.setChecked(SETTINGS['1HKO'])
        except (KeyError, TypeError):
            self.ui.ohkoCheck.setChecked(False)
        
        # Lv1 sword beam
        try:
            self.ui.lv1BeamCheck.setChecked(SETTINGS['Lv1_Beam'])
        except (KeyError, TypeError):
            self.ui.lv1BeamCheck.setChecked(False)
        
        # nice magic rod
        try:
            self.ui.niceRodCheck.setChecked(SETTINGS['Nice_Rod'])
        except (KeyError, TypeError):
            self.ui.niceRodCheck.setChecked(False)
        
        # excluded checks
        try:
            for check in SETTINGS['Excluded_Locations']:
                if check in TOTAL_CHECKS:
                    self.excluded_checks.add(check)
        except (KeyError, TypeError):
            if not self.ui.chestsCheck.isChecked():
                self.excluded_checks.update(MISCELLANEOUS_CHESTS)
            if not self.ui.fishingCheck.isChecked():
                self.excluded_checks.update(FISHING_REWARDS)
            if not self.ui.rapidsCheck.isChecked():
                self.excluded_checks.update(RAPIDS_REWARDS)
            if not self.ui.dampeCheck.isChecked():
                self.excluded_checks.update(DAMPE_REWARDS)
            if not self.ui.giftsCheck.isChecked():
                self.excluded_checks.update(FREE_GIFT_LOCATIONS)
            if not self.ui.tradeGiftsCheck.isChecked():
                self.excluded_checks.update(TRADE_GIFT_LOCATIONS)
            if not self.ui.bossCheck.isChecked():
                self.excluded_checks.update(BOSS_LOCATIONS)
            if not self.ui.miscellaneousCheck.isChecked():
                self.excluded_checks.update(MISC_LOCATIONS)
            if not self.ui.heartsCheck.isChecked():
                self.excluded_checks.update(HEART_PIECE_LOCATIONS)
            if not self.ui.leavesCheck.isChecked():
                self.excluded_checks.update(LEAF_LOCATIONS)
            # if not self.ui.trendyCheck.isChecked():
            #     self.excluded_checks.update(TRENDY_REWARDS)
            # if not self.ui.shopCheck.isChecked():
            #     self.excluded_checks.update(SHOP_ITEMS)
        
        # starting items
        try:
            for item in SETTINGS['Starting_Items']:
                if item in STARTING_ITEMS:
                    if self.starting_gear.count(item) < STARTING_ITEMS.count(item):
                        self.starting_gear.append(item)
        except (KeyError, TypeError):
            self.starting_gear = list() # reset starting gear to default if error
        
        # starting rupees
        try:
            self.ui.rupeesSpinBox.setValue(SETTINGS['Starting_Rupees'])
        except (KeyError, TypeError):
            self.ui.rupeesSpinBox.setValue(0)


    def romBrowse(self):
        folder_path = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
        if os.path.exists(folder_path):
            self.ui.lineEdit.setText(folder_path)
    
    
    def outBrowse(self):
        folder_path = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
        if os.path.exists(folder_path):
            self.ui.lineEdit_2.setText(folder_path)
    
    
    def settingsBrowse(self):
        file_path = QtWidgets.QFileDialog.getOpenFileName(self, 'Select Settings', filter='Text files(*.txt)')[0]
        if os.path.isfile(file_path):
            self.ui.lineEdit_4.setText(file_path)
    
    
    def generateSeed(self):
        adj1 = random.choice(ADJECTIVES)
        adj2 = random.choice(ADJECTIVES)
        char = random.choice(CHARACTERS)
        self.ui.lineEdit_3.setText(adj1 + adj2 + char)
    
    
    def chestsCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(MISCELLANEOUS_CHESTS)
        else:
            self.excluded_checks.update(MISCELLANEOUS_CHESTS)
    
    
    def fishingCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(FISHING_REWARDS)
        else:
            self.excluded_checks.update(FISHING_REWARDS)
    
    
    def rapidsCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(RAPIDS_REWARDS)
            self.excluded_checks.difference_update(['owl-statue-rapids'])
        else:
            self.excluded_checks.update(RAPIDS_REWARDS)
            if self.overworld_owls:
                self.excluded_checks.update(['owl-statue-rapids'])
    
    
    def dampeCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(DAMPE_REWARDS)
        else:
            self.excluded_checks.update(DAMPE_REWARDS)
    
    
    # def trendyCheck_Clicked(self, checked):
    #     if checked:
    #         self.excluded_checks.difference_update(TRENDY_REWARDS)
    #     else:
    #         self.excluded_checks.update(TRENDY_REWARDS)
    
    
    # def shopCheck_Clicked(self, checked):
    #     if checked:
    #         self.excluded_checks.difference_update(SHOP_ITEMS)
    #     else:
    #         self.excluded_checks.update(SHOP_ITEMS)
    
    
    def giftsCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(FREE_GIFT_LOCATIONS)
        else:
            self.excluded_checks.update(FREE_GIFT_LOCATIONS)
    
    
    def tradeQuest_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(TRADE_GIFT_LOCATIONS)
        else:
            self.excluded_checks.update(TRADE_GIFT_LOCATIONS)
    
    
    def bossCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(BOSS_LOCATIONS)
        else:
            self.excluded_checks.update(BOSS_LOCATIONS)
    
    
    def miscellaneousCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(MISC_LOCATIONS)
        else:
            self.excluded_checks.update(MISC_LOCATIONS)
    
    
    def heartsCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(HEART_PIECE_LOCATIONS)
        else:
            self.excluded_checks.update(HEART_PIECE_LOCATIONS)
    

    def leavesCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(LEAF_LOCATIONS)
        else:
            self.excluded_checks.update(LEAF_LOCATIONS)
    

    def rupCheck_Clicked(self):
        self.excluded_checks.difference_update(BLUE_RUPEES)
    

    def updateSeashells(self):
        value = self.ui.seashellsComboBox.currentIndex()
        
        if value == 0:
            self.excluded_checks.update(SEASHELL_REWARDS)
        elif value == 1:
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
            self.excluded_checks.update(['15-seashell-reward', '30-seashell-reward', '40-seashell-reward', '50-seashell-reward'])
        elif value == 2:
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
            self.excluded_checks.update(['30-seashell-reward', '40-seashell-reward', '50-seashell-reward'])
        elif value == 3:
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
            self.excluded_checks.update(['40-seashell-reward', '50-seashell-reward'])
        elif value == 4:
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
            self.excluded_checks.update(['50-seashell-reward'])
        else:
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
    

    def updateOwls(self):
        value = self.ui.owlsComboBox.currentIndex()

        if value == 0:
            self.overworld_owls = False
            self.excluded_checks.difference_update(OVERWORLD_OWLS)
            self.dungeon_owls = False
            self.excluded_checks.difference_update(DUNGEON_OWLS)
        elif value == 1:
            self.overworld_owls = True
            self.dungeon_owls = False
            self.excluded_checks.difference_update(DUNGEON_OWLS)
        elif value == 2:
            self.overworld_owls = False
            self.excluded_checks.difference_update(OVERWORLD_OWLS)
            self.dungeon_owls = True
        else:
            self.overworld_owls = True
            self.dungeon_owls = True
        
        if not self.ui.rapidsCheck.isChecked():
            self.excluded_checks.update(['owl-statue-rapids'])


    def parseExternalSettings(self):
        external_settings = {}
        settings = {}

        try:
            with open(self.ui.lineEdit_4.text(), 'r') as f:
                external_settings = yaml.safe_load(f)
            
            seed = external_settings['Seed']
            if seed.lower().strip() in ('', 'random'):
                random.seed()
                seed = str(random.getrandbits(32))
            
            logic = external_settings['Logic'] if external_settings['Logic'] in LOGIC_PRESETS else 'invalid'
            if logic == 'invalid':
                raise TypeError('')

            settings = {
                'seed': seed,
                'logic': logic,
                'platform': external_settings['Platform'],
                'create-spoiler': external_settings['Create_Spoiler'],
                'free-book': external_settings['Free_Book'],
                'unlocked-bombs': external_settings['Unlocked_Bombs'],
                'shuffle-bombs': external_settings['Shuffled_Bombs'],
                'shuffle-powder': external_settings['Shuffled_Powder'],
                'reduce-farming': external_settings['Reduced_Farming'],
                'fast-fishing': external_settings['Fast_Fishing'],
                'fast-stealing': external_settings['Fast_Stealing'],
                'fast-trendy': external_settings['Fast_Trendy'],
                'fast-songs': external_settings['Fast_Songs'],
                'shuffle-instruments': external_settings['Instruments'],
                'starting-instruments': external_settings['Starting_Instruments'],
                'bad-pets': external_settings['Bad_Pets'],
                'open-kanalet': external_settings['Open_Kanalet'],
                'open-bridge': external_settings['Open_Bridge'],
                'open-mamu': external_settings['Open_Mamu'],
                'traps': external_settings['Traps'],
                'blupsanity': external_settings['Blupsanity'],
                'classic-d2': external_settings['Classic_D2'],
                'owl-overworld-gifts': True if external_settings['Owl_Statues'] in ('overworld', 'all') else False,
                'owl-dungeon-gifts': True if external_settings['Owl_Statues'] in ('dungeons', 'all') else False,
                # 'owl-hints': external_settings[''],
                'fast-stalfos': external_settings['Fast_Stalfos'],
                'scaled-chest-sizes': external_settings['Scaled_Chest_Sizes'],
                'seashells-important': True if len([s for s in SEASHELL_REWARDS if s not in external_settings['Excluded_Locations']]) > 0 else False,
                'trade-important': True if len([t for t in TRADE_GIFT_LOCATIONS if t not in external_settings['Excluded_Locations']]) > 0 else False,
                # 'shuffle-companions': external_settings[''],
                # 'randomize-entrances': external_settings[''],
                'randomize-music': external_settings['Randomize_Music'],
                'randomize-enemies': external_settings['Randomize_Enemies'],
                # 'panel-enemies': True if len([s for s in DAMPE_REWARDS if s not in external_settings['']]) > 0 else False,
                'shuffle-dungeons': external_settings['Shuffled_Dungeons'],
                # 'dungeon-items': external_settings[''],
                '1HKO': external_settings['1HKO'],
                'lv1-beam': external_settings['Lv1_Beam'],
                'nice-rod': external_settings['Nice_Rod'],
                'starting-items': external_settings['Starting_Items'],
                'starting-rupees': external_settings['Starting_Rupees'],
                'excluded-locations': external_settings['Excluded_Locations']
            }
        except (FileNotFoundError, KeyError, TypeError):
            pass

        return settings


    # Randomize Button Clicked
    def randomizeButton_Clicked(self):
        
        # verify RomFS before shuffling items
        rom_path = self.ui.lineEdit.text()

        if not os.path.exists(rom_path):
            self.showUserError('Romfs path does not exist!')
            return
        
        if os.path.exists(os.path.join(rom_path, 'romfs')):
            rom_path = os.path.join(rom_path, 'romfs')
        
        if not os.path.isfile(f'{rom_path}/region_common/event/PlayerStart.bfevfl'):
            self.showUserError('RomFS path is not valid!')
            return
        
        if not os.path.exists(self.ui.lineEdit_2.text()):
            self.showUserError('Output path does not exist!')
            return
        
        if not os.path.isfile(LOGIC_PATH):
            self.showUserError('Logic file not found!')
            return
        
        logic_file = yaml.safe_load(self.logic_defs)
        
        seed = self.ui.lineEdit_3.text()
        if seed.lower().strip() in ('', 'random'):
            random.seed()
            seed = str(random.getrandbits(32))
                
        logic = LOGIC_PRESETS[self.ui.tricksComboBox.currentIndex()]
        
        external_settings = {}
        if self.ui.externalSettingsCheck.isChecked():
            external_settings = self.parseExternalSettings()
            if not external_settings:
                self.showUserError('Could not read the external settings file!')
                return
        
        settings = {
            'seed': seed,
            'logic': logic,
            'platform': PLATFORMS[self.ui.platformComboBox.currentIndex()],
            'create-spoiler': self.ui.spoilerCheck.isChecked(),
            'free-book': self.ui.bookCheck.isChecked(),
            'unlocked-bombs': self.ui.unlockedBombsCheck.isChecked(),
            'shuffle-bombs': self.ui.shuffledBombsCheck.isChecked(),
            'shuffle-powder': self.ui.shuffledPowderCheck.isChecked(),
            'reduce-farming': self.ui.farmingCheck.isChecked(),
            'fast-fishing': self.ui.fastFishingCheck.isChecked(),
            'fast-stealing': self.ui.stealingCheck.isChecked(),
            'fast-trendy': self.ui.fastTrendyCheck.isChecked(),
            'fast-songs': self.ui.songsCheck.isChecked(),
            'shuffle-instruments': self.ui.instrumentCheck.isChecked(),
            'starting-instruments': self.ui.instrumentsComboBox.currentIndex(),
            'bad-pets': self.ui.badPetsCheck.isChecked(),
            'open-kanalet': self.ui.kanaletCheck.isChecked(),
            'open-bridge': self.ui.bridgeCheck.isChecked(),
            'open-mamu': self.ui.mazeCheck.isChecked(),
            'traps': TRAP_SETTINGS[self.ui.trapsComboBox.currentIndex()],
            'blupsanity': self.ui.rupCheck.isChecked(),
            'classic-d2': self.ui.swampCheck.isChecked(),
            'owl-overworld-gifts': self.overworld_owls,
            'owl-dungeon-gifts': self.dungeon_owls,
            # 'owl-hints': True if OWLS_SETTINGS[self.ui.owlsComboBox.currentIndex()] in ['hints', 'hybrid'] else False,
            'fast-stalfos': self.ui.stalfosCheck.isChecked(),
            'scaled-chest-sizes': self.ui.chestSizesCheck.isChecked(),
            'seashells-important': True if len([s for s in SEASHELL_REWARDS if s not in self.excluded_checks]) > 0 else False,
            'trade-important': True if len([t for t in TRADE_GIFT_LOCATIONS if t not in self.excluded_checks]) > 0 else False,
            # 'shuffle-companions': self.ui.companionCheck.isChecked(),
            # 'randomize-entrances': self.ui.loadingCheck.isChecked(),
            'randomize-music': self.ui.musicCheck.isChecked(),
            'randomize-enemies': self.ui.enemyCheck.isChecked(),
            # 'panel-enemies': True if len([s for s in DAMPE_REWARDS if s not in self.excluded_checks]) > 0 else False,
            'shuffle-dungeons': self.ui.dungeonsCheck.isChecked(),
            # 'dungeon-items': DUNGEON_ITEM_SETTINGS[self.ui.itemsComboBox.currentIndex()],
            '1HKO': self.ui.ohkoCheck.isChecked(),
            'lv1-beam': self.ui.lv1BeamCheck.isChecked(),
            'nice-rod': self.ui.niceRodCheck.isChecked(),
            'starting-items': self.starting_gear,
            'starting-rupees': self.ui.rupeesSpinBox.value(),
            'excluded-locations': self.excluded_checks
        }
        
        if external_settings:
            if external_settings.keys() != settings.keys():
                self.showUserError('External settings file is missing data!')
                return
            settings = external_settings
        
        outdir = f"{self.ui.lineEdit_2.text()}/{settings['seed']}"
        self.progress_window = ProgressWindow(rom_path, outdir, ITEM_DEFS, logic_file, settings)
        self.progress_window.setFixedSize(472, 125)
        self.progress_window.setWindowTitle(f"{settings['seed']}")

        if self.mode == 'light':
            self.progress_window.setStyleSheet(LIGHT_STYLESHEET)
        else:
            self.progress_window.setStyleSheet(DARK_STYLESHEET)
        
        self.progress_window.show()
    
    
    # Tab changed
    def tab_Changed(self):

        # starting items
        if self.ui.tabWidget.currentIndex() == 1:
            randomized_gear = STARTING_ITEMS[:]
            for x in self.starting_gear:
                randomized_gear.remove(x)
            
            self.ui.listWidget_5.clear()
            for item in randomized_gear:
                self.ui.listWidget_5.addItem(self.checkToList(str(item)))
            
            self.ui.listWidget_6.clear()
            for item in self.starting_gear:
                self.ui.listWidget_6.addItem(self.checkToList(str(item)))
            
            return
        
        # locations
        if self.ui.tabWidget.currentIndex() == 2:
            self.ui.listWidget.clear()
            for check in TOTAL_CHECKS.difference(self.excluded_checks):
                if check in DUNGEON_OWLS and not self.dungeon_owls:
                    continue
                if check in OVERWORLD_OWLS and not self.overworld_owls:
                    continue
                if check in BLUE_RUPEES and not self.ui.rupCheck.isChecked():
                    continue
                self.ui.listWidget.addItem(SmartListWidget(self.checkToList(str(check))))
            
            self.ui.listWidget_2.clear()
            for check in self.excluded_checks:
                if check in DUNGEON_OWLS and not self.dungeon_owls:
                    continue
                if check in OVERWORLD_OWLS and not self.overworld_owls:
                    continue
                if check in BLUE_RUPEES and not self.ui.rupCheck.isChecked():
                    continue
                self.ui.listWidget_2.addItem(SmartListWidget(self.checkToList(str(check))))
            
            return
        
        # logic tricks
        if self.ui.tabWidget.currentIndex() == 3:
            return
    
    
    # Locations Include Button Clicked
    def includeButton_Clicked(self):
        for i in self.ui.listWidget_2.selectedItems():
            self.ui.listWidget_2.takeItem(self.ui.listWidget_2.row(i))
            self.excluded_checks.remove(self.listToCheck(i.text()))
            self.ui.listWidget.addItem(SmartListWidget(i.text()))
    
    
    # Locations Exclude Button Clicked
    def excludeButton_Clicked(self):
        for i in self.ui.listWidget.selectedItems():
            self.ui.listWidget.takeItem(self.ui.listWidget.row(i))
            self.ui.listWidget_2.addItem(SmartListWidget(i.text()))
            self.excluded_checks.add(self.listToCheck(i.text()))
    
    
    # Starting Items Include Button Clicked - 'including' is moving starting items into the randomized pool
    def includeButton_3_Clicked(self):
        for i in self.ui.listWidget_6.selectedItems():
            self.ui.listWidget_6.takeItem(self.ui.listWidget_6.row(i))
            self.starting_gear.remove(self.listToItem(i.text()))
            self.ui.listWidget_5.addItem(i.text())


    # Starting Items Exclude Button Clicked - 'excluding' is moving randomized items into starting items
    def excludeButton_3_Clicked(self):
        for i in self.ui.listWidget_5.selectedItems():
            self.ui.listWidget_5.takeItem(self.ui.listWidget_5.row(i))
            self.ui.listWidget_6.addItem(i.text())
            self.starting_gear.append(self.listToItem(i.text()))


    # some-check to Some Check
    def checkToList(self, check):
        # slots = ('1St', '2Nd', '3Rd', '4Th', '5Th', '6Th', '7Th')

        s = sub("-", " ", check).title()

        # for slot in slots:
        #     s = s.replace(slot, slot.lower())
        
        return s
    
    
    # Some Check to some-check
    def listToCheck(self, check):
        stayUpper = ('d0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8')
        
        s = sub(" ", "-", check).lower()
        
        if s.startswith(stayUpper):
            s = s.replace('d', 'D', 1)
        
        return s
    

    # Starting Item to starting-item and also converts names that were changed to look nicer
    def listToItem(self, item):
        s = sub(" ", "-", item).lower()
        
        return s
    

    # Sets the app to Light Mode
    def setLightMode(self):
        self.mode = str('light')
        self.setStyleSheet(LIGHT_STYLESHEET)
        if self.ui.explainationLabel.text() == 'Hover over an option to see what it does':
            self.ui.explainationLabel.setStyleSheet('color: rgb(80, 80, 80);')
        else:
            self.ui.explainationLabel.setStyleSheet('color: black;')
    

    # Sets the app to Dark Mode
    def setDarkMode(self):
        self.mode = str('dark')
        self.setStyleSheet(DARK_STYLESHEET)
        if self.ui.explainationLabel.text() == 'Hover over an option to see what it does':
            self.ui.explainationLabel.setStyleSheet('color: rgb(175, 175, 175);')
        else:
            self.ui.explainationLabel.setStyleSheet('color: white;')
    

    # Display new window listing the new features and bug fixes
    def showChangelog(self):
        message = QtWidgets.QMessageBox()
        message.setWindowTitle("What's New")
        message.setText(CHANGE_LOG)

        if self.mode == 'light':
            message.setStyleSheet(LIGHT_STYLESHEET)
        else:
            message.setStyleSheet(DARK_STYLESHEET)
        
        message.exec()
    

    # Display new window to let the user know what went wrong - missing romfs/output path, bad custom logic, etc.
    def showUserError(self, msg):
        message = QtWidgets.QMessageBox()
        message.setWindowTitle("Error")
        message.setText(msg)

        if self.mode == 'light':
            message.setStyleSheet(LIGHT_STYLESHEET)
        else:
            message.setStyleSheet(DARK_STYLESHEET)
        
        message.exec()
    

    # Display new window listing the currently known issues
    def showIssues(self):
        message = QtWidgets.QMessageBox()
        message.setWindowTitle("Known Issues")
        message.setText(KNOWN_ISSUES)

        if self.mode == 'light':
            message.setStyleSheet(LIGHT_STYLESHEET)
        else:
            message.setStyleSheet(DARK_STYLESHEET)
        
        message.exec()
    

    def showInfo(self):
        message = QtWidgets.QMessageBox()
        message.setWindowTitle("Link's Awakening Switch Randomizer")
        message.setText(ABOUT_INFO)

        if self.mode == 'light':
            message.setStyleSheet(LIGHT_STYLESHEET)
        else:
            message.setStyleSheet(DARK_STYLESHEET)
        
        message.exec()
    

    # Override mouse click event to make certain stuff lose focus
    def mousePressEvent(self, event):
        focused_widget = self.focusWidget()
        if isinstance(focused_widget, QtWidgets.QLineEdit) |\
            isinstance(focused_widget, QtWidgets.QComboBox) |\
            isinstance(focused_widget, QtWidgets.QSpinBox):
                focused_widget.clearFocus()
    

    # Override close event to save settings
    def closeEvent(self, event):
        self.saveSettings()
        event.accept()



# Create custom QComboBox to signal when the popup is closed, regardless of how
class SmartComboBox(QtWidgets.QComboBox):
    popup_closed = QtCore.Signal()

    def hidePopup(self):
        QtWidgets.QComboBox.hidePopup(self)
        self.popup_closed.emit()



# Create custom QListWidgetItem to sort locations alphanumerically
class SmartListWidget(QtWidgets.QListWidgetItem):
    def __lt__(self, other):
        try:
            dungeon_checks = ('D0', 'D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8')

            nums_a = [c for c in self.text() if c.isdigit()]
            nums_a = "".join(nums_a)
            str_a = [c for c in self.text() if not c.isdigit()]
            a = int(nums_a)

            nums_b = [c for c in other.text() if c.isdigit()]
            nums_b = "".join(nums_b)
            str_b = [c for c in other.text() if not c.isdigit()]
            b = int(nums_b)
            
            if self.text().startswith(dungeon_checks) and other.text().startswith(dungeon_checks):
                d = [d for d in dungeon_checks if self.text().startswith(d)]
                if not other.text().startswith(d[0]):
                    return int(nums_a[0]) < int(nums_b[0])
                else:
                    a = int(nums_a[1:])
                    b = int(nums_b[1:])
                    if str_a != str_b:
                        raise ValueError('')
                    return a < b
            if self.text().startswith(dungeon_checks) or other.text().startswith(dungeon_checks):
                raise TypeError('')
            
            if str_a == str_b:
                if self.text().startswith(nums_a) and other.text().startswith(nums_b):
                    return a < b
                if self.text().endswith(nums_a) and other.text().endswith(nums_b):
                    return a < b
            
            raise TypeError('')
        
        except (IndexError, TypeError, ValueError):
            locations = [self.text(), other.text()]
            locations.sort()
            
            if self.text() == locations[0]:
                return True
            else:
                return False



class MyDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, indentless)
