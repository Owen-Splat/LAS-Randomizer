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
        self.update_pending = bool(False)
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
        
        # if running a build, check and read updated/edited logic file
        # if it doesn't exist, we just use the built-in logic for the build
        if not IS_RUNNING_FROM_SOURCE:
            if os.path.isfile(LOGIC_PATH):
                with open(LOGIC_PATH, 'r') as f:
                    self.logic_defs = f.read()
                    f.seek(0)
                    try:
                        self.logic_version = float(f.readline().strip('#'))
                    except TypeError:
                        self.logic_version = LOGIC_VERSION
        
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
        self.ui.actionUpdate.triggered.connect(self.checkLogic)
        self.ui.actionExport.triggered.connect(self.exportLogic)
        self.ui.actionLight.triggered.connect(self.setLightMode)
        self.ui.actionDark.triggered.connect(self.setDarkMode)
        self.ui.actionChangelog.triggered.connect(self.showChangelog)
        self.ui.actionKnown_Issues.triggered.connect(self.showIssues)
        # folder browsing, seed generation, and randomize button
        self.ui.browseButton1.clicked.connect(self.romBrowse)
        self.ui.browseButton2.clicked.connect(self.outBrowse)
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
        self.setFixedSize(780, 640)
        self.setWindowTitle(f'{self.windowTitle()} v0.3.0-rc2') # {VERSION}')
        
        # self.ui.retranslateUi(self)
        
        self.show()
        
        if IS_RUNNING_FROM_SOURCE:
            self.ui.updateChecker.setText('Running from source. No updates will be checked')
        else:
            self.process = UpdateProcess() # initialize a new QThread class
            self.process.can_update.connect(self.showUpdate) # connect a boolean signal to showUpdate()
            self.process.start() # start the thread



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
    


    # event filter for showing option info onto label
    def eventFilter(self, source, event):

        # Display description text of items when hovered over
        if event.type() == QtCore.QEvent.Type.HoverEnter:
            self.ui.explainationLabel.setText(source.whatsThis())
            if self.mode == 'light':
                self.ui.explainationLabel.setStyleSheet('color: black;')
            else:
                self.ui.explainationLabel.setStyleSheet('color: white;')
        
        # Display default text when item is no longer hovered over
        elif event.type() == QtCore.QEvent.Type.HoverLeave:
            self.ui.explainationLabel.setText('Hover over an option to see what it does')
            if self.mode == 'light':
                self.ui.explainationLabel.setStyleSheet('color: rgb(80, 80, 80);')
            else:
                self.ui.explainationLabel.setStyleSheet('color: rgb(175, 175, 175);')
        
        return QtWidgets.QWidget.eventFilter(self, source, event)
    


    # show update if there is one
    def showUpdate(self, update):
        if update:
            self.update_pending = True
            self.ui.updateChecker.setText(f"<a href='{DOWNLOAD_PAGE}'>Update found!</a>")
        else:
            self.ui.updateChecker.setText('No updates available')
    


    def checkLogic(self):
        if self.update_pending: # ignore logic changes if there is an app update
            self.showLogicUpdate(False)
            return
        
        self.logic_process = LogicUpdateProcess(ver=self.logic_version) # initialize a new QThread class
        self.logic_process.can_update.connect(self.showLogicUpdate) # connect a boolean signal to showLogicUpdate()
        self.logic_process.give_logic.connect(self.obtainLogic) # connect a tuple signal to obtainLogic()
        self.logic_process.start() # start the thread
        self.logic_process.exec() # wait on updater
    


    def obtainLogic(self, version_and_logic):
        self.logic_version = version_and_logic[0]
        self.logic_defs = version_and_logic[1]
        with open(LOGIC_PATH, 'w+') as f:
            f.write(f'# {self.logic_version}\n')
            f.write(self.logic_defs)



    def showLogicUpdate(self, update):
        message = QtWidgets.QMessageBox()
        message.setWindowTitle("Logic Updater")
        
        if self.mode == 'light':
            message.setStyleSheet(LIGHT_STYLESHEET)
        else:
            message.setStyleSheet(DARK_STYLESHEET)
        
        if update:
            message.setText('Logic has updated')
        else:
            message.setText('No updates found')
        
        message.exec()



    def exportLogic(self):
        filename = QtWidgets.QFileDialog.getSaveFileName(self, 'Save As', '.', "YAML (*.yml)") # ;;TEXT (*.txt)")
        if filename[0] != '':
            with open(filename[0], 'w') as f:
                f.write(self.logic_defs)
                # yaml.dump(yaml.safe_load(self.logic_defs), f, Dumper=MyDumper, sort_keys=False, width=float('inf'))



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
    
        self.starting_gear = list() # fully reset starting items
        self.ui.rupeesSpinBox.setValue(0)

        self.tab_Changed() # just call the same event as when changing the tab to refresh the list



    def saveSettings(self):
        settings_dict = {
            'Theme': self.mode,
            'Romfs_Folder': self.ui.lineEdit.text(),
            'Output_Folder': self.ui.lineEdit_2.text(),
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


    
    # RomFS Folder Browse
    def romBrowse(self):
        folderpath = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
        if folderpath != "":
            self.ui.lineEdit.setText(folderpath)
    
    
    
    # Output Folder Browse
    def outBrowse(self):
        folderpath = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
        if folderpath != "":
            self.ui.lineEdit_2.setText(folderpath)
    
    
    
    # Generate New Seed
    def generateSeed(self):
        adj1 = random.choice(ADJECTIVES)
        adj2 = random.choice(ADJECTIVES)
        char = random.choice(CHARACTERS)
        self.ui.lineEdit_3.setText(adj1 + adj2 + char)
    
    
    
    # Chests Check Changed
    def chestsCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(MISCELLANEOUS_CHESTS)
        else:
            self.excluded_checks.update(MISCELLANEOUS_CHESTS)
    
    
    
    # Fishing Check Changed
    def fishingCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(FISHING_REWARDS)
        else:
            self.excluded_checks.update(FISHING_REWARDS)
    
    
    
    # Rapids Check Changed
    def rapidsCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(RAPIDS_REWARDS)
            self.excluded_checks.difference_update(['owl-statue-rapids'])
        else:
            self.excluded_checks.update(RAPIDS_REWARDS)
            if self.overworld_owls:
                self.excluded_checks.update(['owl-statue-rapids'])
    
    
    
    # Dampe Check Changed
    def dampeCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(DAMPE_REWARDS)
        else:
            self.excluded_checks.update(DAMPE_REWARDS)
    
    
    
    # # Trendy Check Changed
    # def trendyCheck_Clicked(self, checked):
    #     if checked:
    #         self.excluded_checks.difference_update(TRENDY_REWARDS)
    #     else:
    #         self.excluded_checks.update(TRENDY_REWARDS)
    
    
    
    # # Shop Check Changed
    # def shopCheck_Clicked(self, checked):
    #     if checked:
    #         self.excluded_checks.difference_update(SHOP_ITEMS)
    #     else:
    #         self.excluded_checks.update(SHOP_ITEMS)
    
    
    
    # Gifts Check Changed
    def giftsCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(FREE_GIFT_LOCATIONS)
        else:
            self.excluded_checks.update(FREE_GIFT_LOCATIONS)
    
    
    
    # Trade Quest Check Changed
    def tradeQuest_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(TRADE_GIFT_LOCATIONS)
        else:
            self.excluded_checks.update(TRADE_GIFT_LOCATIONS)
    
    
    
    # Bosses Check Changed
    def bossCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(BOSS_LOCATIONS)
        else:
            self.excluded_checks.update(BOSS_LOCATIONS)
    
    
    
    # Miscellaneous Standing Items Check Changed
    def miscellaneousCheck_Clicked(self, checked):
        if checked:
            self.excluded_checks.difference_update(MISC_LOCATIONS)
        else:
            self.excluded_checks.update(MISC_LOCATIONS)
    
    
    
    # Heart Pieces Check Changed
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
        # regardless of if it's checked or not, reset blue rupees
        # switching to the locations tab will handle if it shows or not
        self.excluded_checks.difference_update(BLUE_RUPEES)
    


    # Update Number of Max Seashells
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
    


    # Update which owls show up in the locations tab
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



    # Randomize Button Clicked
    def randomizeButton_Clicked(self):
        
        if not os.path.exists(self.ui.lineEdit.text()):
            self.showUserError('Romfs path does not exist!')
            return
        
        # verify RomFS before shuffling items
        rom_path = self.ui.lineEdit.text()
        
        if os.path.exists(os.path.join(rom_path, 'romfs')):
            rom_path = os.path.join(rom_path, 'romfs')
        
        if not os.path.isfile(f'{rom_path}/region_common/event/PlayerStart.bfevfl'):
            self.showUserError('RomFS path is not valid!')
            return
        
        if not os.path.exists(self.ui.lineEdit_2.text()):
            self.showUserError('Output path does not exist!')
            return
        
        # if user deleted the external logic file, reset to the built-in logic
        if not os.path.isfile(LOGIC_PATH):
            self.logic_defs = LOGIC_RAW
            self.logic_version = LOGIC_VERSION
        
        logic_file = yaml.safe_load(self.logic_defs)
        
        seed = self.ui.lineEdit_3.text()
        if seed.lower().strip() in ('', 'random'):
            random.seed()
            seed = str(random.getrandbits(32))
        
        outdir = f"{self.ui.lineEdit_2.text()}/{seed}"
        
        logic = LOGIC_PRESETS[self.ui.tricksComboBox.currentIndex()]
        
        settings = {
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
            'starting-items': self.starting_gear,
            'starting-rupees': self.ui.rupeesSpinBox.value(),
            'excluded-locations': self.excluded_checks
        }
        
        self.progress_window = ProgressWindow(rom_path, outdir, seed, logic, ITEM_DEFS, logic_file, settings)
        self.progress_window.setFixedSize(472, 125)
        self.progress_window.setWindowTitle(f"{seed}")

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
