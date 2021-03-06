from PySide6 import QtCore, QtWidgets
from UI.ui_form import Ui_MainWindow
from UI.progress_window import ProgressWindow
from update import UpdateProcess
from randomizer_paths import SETTINGS_PATH, IS_RUNNING_FROM_SOURCE
from randomizer_data import *

import yaml
from indentation import MyDumper

import os
import random
from re import sub



class MainWindow(QtWidgets.QMainWindow):
    
    def __init__(self):
        super (MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Styling
        for b in self.findChildren(QtWidgets.QPushButton):
            b.setStyleSheet("QPushButton {background-color: rgb(218, 218, 218)}"
                            "QPushButton {border: 1px solid black}"
                            "QPushButton {color: black}"
                            "QPushButton:hover {background-color: rgb(200, 200, 200)}"
                            "QPushButton:pressed {background-color: rgb(175, 175, 175)}")

        # Keep track of stuff
        self.max_seashells = int(15)
        self.excluded_checks = set()
        self.logic = str('basic')
        self.mode = str('dark')

        # Load User Settings
        if not DEFAULTS:
            self.loadSettings()
        else:
            self.applyDefaults()
        
        if self.mode == 'light':
            self.setStyleSheet(qdarktheme.load_stylesheet('light'))
            self.ui.explainationLabel.setStyleSheet('color: rgb(80, 80, 80);')
        else:
            self.setStyleSheet(qdarktheme.load_stylesheet('dark'))
            self.ui.explainationLabel.setStyleSheet('color: rgb(175, 175, 175);')

        ### SUBSCRIBE TO EVENTS
        
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
        self.ui.giftsCheck.clicked.connect(self.giftsCheck_Clicked)
        self.ui.tradeGiftsCheck.clicked.connect(self.tradeQuest_Clicked)
        self.ui.bossCheck.clicked.connect(self.bossCheck_Clicked)
        self.ui.miscellaneousCheck.clicked.connect(self.miscellaneousCheck_Clicked)
        self.ui.heartsCheck.clicked.connect(self.heartsCheck_Clicked)
        self.ui.horizontalSlider.valueChanged.connect(self.updateSeashells)
        self.ui.horizontalSlider_2.valueChanged.connect(self.updateLogic)
        # locations tab
        self.ui.tabWidget.currentChanged.connect(self.tab_Changed)
        self.ui.includeButton.clicked.connect(self.includeButton_Clicked)
        self.ui.excludeButton.clicked.connect(self.excludeButton_Clicked)
        
        ### DESCRIPTIONS
        self.checkBoxes = self.ui.tab.findChildren(QtWidgets.QCheckBox)
        self.checkBoxes.extend([self.ui.label_6, self.ui.horizontalSlider])
        self.checkBoxes.extend([self.ui.label_11, self.ui.horizontalSlider_2])
        for check in self.checkBoxes:
            check.installEventFilter(self)
        
        ### show and check for updates
        self.setFixedSize(780, 640)
        self.show()

        if IS_RUNNING_FROM_SOURCE:
            self.ui.updateChecker.setText('Running from source. No updates will be checked')
        else:
            self.process = UpdateProcess() # initialize a new QThread class
            self.process.can_update.connect(self.showUpdate) # connect a boolean signal to ShowUpdate()
            self.process.start() # start the thread


    
    # event filter for showing option info onto label
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
    
    
    
    # show update if there is one
    def showUpdate(self, update):
        if update:
            self.ui.updateChecker.setText("<a href='https://github.com/Owen-Splat/LAS-Randomizer/releases/latest'>Update found!</a>")
        else:
            self.ui.updateChecker.setText('No updates available')
    
    
    
    ### STORED SETTINGS
    # apply stored settings or defaults
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
            checked = SETTINGS['Fishing']
            self.ui.fishingCheck.setChecked(checked)
        except (KeyError, TypeError):
            self.ui.fishingCheck.setChecked(True)
        
        # fast fishing
        try:
            self.ui.fastFishingCheck.setChecked(SETTINGS['Fast-Fishing'])
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
        
        # starting instruments
        try:
            self.ui.instrumentsComboBox.setCurrentIndex(SETTINGS['Starting_Instruments'])
        except (KeyError, TypeError):
            self.ui.instrumentsComboBox.setCurrentIndex(0)

        # seashells
        try:
            num = SETTINGS['Seashells']
            if num == 0:
                self.max_seashells = 0
                self.ui.horizontalSlider.setValue(0)
            elif num == 5:
                self.max_seashells = 5
                self.ui.horizontalSlider.setValue(1)
            elif num == 15:
                self.max_seashells = 15
                self.ui.horizontalSlider.setValue(2)
            elif num == 30:
                self.max_seashells = 30
                self.ui.horizontalSlider.setValue(3)
            elif num == 40:
                self.max_seashells = 40
                self.ui.horizontalSlider.setValue(4)
            elif num == 50:
                self.max_seashells = 50
                self.ui.horizontalSlider.setValue(5)
            else:
                self.max_seashells = 15
                self.ui.horizontalSlider.setValue(2)
        except (KeyError, TypeError):
            self.max_seashells = 15
            self.ui.horizontalSlider.setValue(2)
        
        self.ui.label_6.setText("  Max Seashells: {}".format(self.max_seashells))
        
        # logic
        try:
            logic = str(SETTINGS['Logic'].lower())
            if logic in ['basic', 'advanced', 'glitched', 'death', 'none']:
                self.logic = logic
                if logic == 'basic':
                    self.ui.horizontalSlider_2.setValue(0)
                    self.ui.label_11.setText('  Logic:  Basic')
                elif logic == 'advanced':
                    self.ui.horizontalSlider_2.setValue(1)
                    self.ui.label_11.setText('  Logic:  Advanced')
                elif logic == 'glitched':
                    self.ui.horizontalSlider_2.setValue(2)
                    self.ui.label_11.setText('  Logic:  Glitched')
                elif logic == 'death':
                    self.ui.horizontalSlider_2.setValue(3)
                    self.ui.label_11.setText('  Logic:  Death')
                else:
                    self.ui.horizontalSlider_2.setValue(4)
                    self.ui.label_11.setText('  Logic:  None')
            else:
                self.logic = 'basic'
                self.ui.horizontalSlider_2.setValue(0)
                self.ui.label_11.setText('  Logic:  Basic')
        except (KeyError, TypeError):
            self.logic = 'basic'
            self.ui.horizontalSlider_2.setValue(0)
            self.ui.label_11.setText('  Logic:  Basic')
        
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
        
        # reduced farming
        try:
            self.ui.farmingCheck.setChecked(SETTINGS['Reduced_Farming'])
        except (KeyError, TypeError):
            self.ui.farmingCheck.setChecked(True)
        
        # vanilla start
        try:
            self.ui.vanillaCheck.setChecked(SETTINGS['Vanilla_Start'])
        except (KeyError, TypeError):
            self.ui.vanillaCheck.setChecked(True)
        
        # open kanalet
        try:
            self.ui.kanaletCheck.setChecked(SETTINGS['Open_Kanalet'])
        except (KeyError, TypeError):
            self.ui.kanaletCheck.setChecked(True)
        
        # # fast songs
        # try:
        #     self.ui.songsCheck.setChecked(SETTINGS['Fast_Songs'])
        # except (KeyError, TypeError):
        #     self.ui.songsCheck.setChecked(False)

        # shuffled tunics
        try:
            self.ui.tunicsCheck.setChecked(SETTINGS['Shuffled_Tunics'])
        except (KeyError, TypeError):
            self.ui.tunicsCheck.setChecked(True)

        # zap sanity
        try:
            self.ui.zapsCheck.setChecked(SETTINGS['Zapsanity'])
        except (KeyError, TypeError):
            self.ui.zapsCheck.setChecked(False)
        
        # color dungeon rupees
        try:
            self.ui.rupCheck.setChecked(SETTINGS['Blupsanity'])
        except(KeyError, TypeError):
            self.ui.rupCheck.setChecked(False)
        
        # # randomize entances
        # try:
        #     self.ui.loadingCheck.setChecked(SETTINGS['Randomize_Entrances'])
        # except (KeyError, TypeError):
        #     self.ui.loadingCheck.setChecked(False)

        # randomize music
        try:
            self.ui.musicCheck.setChecked(SETTINGS['Randomize_Music'])
        except (KeyError, TypeError):
            self.ui.musicCheck.setChecked(False)

        # spoiler log
        try:
            self.ui.spoilerCheck.setChecked(SETTINGS['Create_Spoiler'])
        except (KeyError, TypeError):
            self.ui.spoilerCheck.setChecked(True)
        
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
            if not self.ui.trendyCheck.isChecked():
                self.excluded_checks.update(TRENDY_REWARDS)    
    

    
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

        self.ui.instrumentCheck.setChecked(True)
        
        self.ui.label_6.setText("  Max Seashells: 15")
        self.ui.horizontalSlider.setValue(2)
        self.max_seashells = 15
        self.excluded_checks.difference_update(set(['5-seashell-reward', '15-seashell-reward']))
        self.excluded_checks.update(set(['30-seashell-reward', '40-seashell-reward', '50-seashell-reward']))

        self.ui.label_11.setText('  Logic:  Basic')
        self.ui.horizontalSlider_2.setValue(0)
        self.logic = 'Basic'

        self.ui.bookCheck.setChecked(True)
        self.ui.unlockedBombsCheck.setChecked(True)
        self.ui.shuffledBombsCheck.setChecked(False)
        self.ui.fastTrendyCheck.setChecked(False)
        self.ui.stealingCheck.setChecked(True)
        self.ui.farmingCheck.setChecked(True)
        self.ui.vanillaCheck.setChecked(True)
        self.ui.musicCheck.setChecked(False)
        self.ui.spoilerCheck.setChecked(True)
        self.ui.kanaletCheck.setChecked(True)
        self.ui.tunicsCheck.setChecked(True)
        self.ui.zapsCheck.setChecked(False)
        self.ui.rupCheck.setChecked(False)

        self.excluded_checks.update(TRENDY_REWARDS)
        self.excluded_checks.update(TRADE_GIFT_LOCATIONS)
        
        self.tab_Changed() # just call the same event as when changing the tab to refresh the list
    
    
    
    # save settings to file
    def saveSettings(self):
        
        settings_dict = {
            'Theme': self.mode,
            'Romfs_Folder': self.ui.lineEdit.text(),
            'Output_Folder': self.ui.lineEdit_2.text(),
            'Seed': self.ui.lineEdit_3.text(),
            'Logic': self.logic,
            'Create_Spoiler': self.ui.spoilerCheck.isChecked(),
            'NonDungeon_Chests': self.ui.chestsCheck.isChecked(),
            'Fishing': self.ui.fishingCheck.isChecked(),
            'Rapids': self.ui.rapidsCheck.isChecked(),
            'Dampe': self.ui.dampeCheck.isChecked(),
            'Free_Gifts': self.ui.giftsCheck.isChecked(),
            'Trade_Quest': self.ui.tradeGiftsCheck.isChecked(),
            'Boss_Drops': self.ui.bossCheck.isChecked(),
            'Miscellaneous': self.ui.miscellaneousCheck.isChecked(),
            'Heart_Pieces': self.ui.heartsCheck.isChecked(),
            'Instruments': self.ui.instrumentCheck.isChecked(),
            'Starting_Instruments': self.ui.instrumentsComboBox.currentIndex(),
            'Seashells': self.max_seashells,
            'Free_Book': self.ui.bookCheck.isChecked(),
            'Unlocked_Bombs': self.ui.unlockedBombsCheck.isChecked(),
            'Shuffled_Bombs': self.ui.shuffledBombsCheck.isChecked(),
            'Fast_Fishing': self.ui.fastFishingCheck.isChecked(),
            'Fast_Stealing': self.ui.stealingCheck.isChecked(),
            'Fast_Trendy': self.ui.fastTrendyCheck.isChecked(),
            'Reduced_Farming': self.ui.farmingCheck.isChecked(),
            'Vanilla_Start': self.ui.vanillaCheck.isChecked(),
            'Open_Kanalet': self.ui.kanaletCheck.isChecked(),
            # 'Fast_Songs': self.ui.songsCheck.isChecked(),
            'Shuffled_Tunics': self.ui.tunicsCheck.isChecked(),
            'Zapsanity': self.ui.zapsCheck.isChecked(),
            'Blupsanity': self.ui.rupCheck.isChecked(),
            # 'Randomize_Entrances': self.ui.loadingCheck.isChecked(),
            'Randomize_Music': self.ui.musicCheck.isChecked(),
            'Excluded_Locations': list(self.excluded_checks)
        }
        
        with open(SETTINGS_PATH, 'w') as settingsFile:
            yaml.dump(settings_dict, settingsFile, Dumper=MyDumper, sort_keys=False)
    
    
    
    ###############################################################################################################################
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
    def chestsCheck_Clicked(self):
        if self.ui.chestsCheck.isChecked():
            self.excluded_checks.difference_update(MISCELLANEOUS_CHESTS)
        else:
            self.excluded_checks.update(MISCELLANEOUS_CHESTS)
    
    
    
    # Fishing Check Changed
    def fishingCheck_Clicked(self):
        if self.ui.fishingCheck.isChecked():
            self.excluded_checks.difference_update(FISHING_REWARDS)
        else:
            self.excluded_checks.update(FISHING_REWARDS)
    
    
    
    # Rapids Check Changed
    def rapidsCheck_Clicked(self):
        if self.ui.rapidsCheck.isChecked():
            self.excluded_checks.difference_update(RAPIDS_REWARDS)
        else:
            self.excluded_checks.update(RAPIDS_REWARDS)
    
    
    
    # Dampe Check Changed
    def dampeCheck_Clicked(self):
        if self.ui.dampeCheck.isChecked():
            self.excluded_checks.difference_update(DAMPE_REWARDS)
        else:
            self.excluded_checks.update(DAMPE_REWARDS)
    
    
    
    # Gifts Check Changed
    def giftsCheck_Clicked(self):
        if self.ui.giftsCheck.isChecked():
            self.excluded_checks.difference_update(FREE_GIFT_LOCATIONS)
        else:
            self.excluded_checks.update(FREE_GIFT_LOCATIONS)
    
    
    
    # Lens Check Changed
    def tradeQuest_Clicked(self):
        if self.ui.tradeGiftsCheck.isChecked():
            self.excluded_checks.difference_update(TRADE_GIFT_LOCATIONS)
        else:
            self.excluded_checks.update(TRADE_GIFT_LOCATIONS)
    
    
    
    # Bosses Check Changed
    def bossCheck_Clicked(self):
        if self.ui.bossCheck.isChecked():
            self.excluded_checks.difference_update(BOSS_LOCATIONS)
        else:
            self.excluded_checks.update(BOSS_LOCATIONS)
    
    
    
    # Miscellaneous Standing Items Check Changed
    def miscellaneousCheck_Clicked(self):
        if self.ui.miscellaneousCheck.isChecked():
            self.excluded_checks.difference_update(MISC_LOCATIONS)
        else:
            self.excluded_checks.update(MISC_LOCATIONS)
    
    
    
    # Heart Pieces Check Changed
    def heartsCheck_Clicked(self):
        if self.ui.heartsCheck.isChecked():
            self.excluded_checks.difference_update(HEART_PIECE_LOCATIONS)
        else:
            self.excluded_checks.update(HEART_PIECE_LOCATIONS)



    # Update Number of Max Seashells
    def updateSeashells(self):
        value = self.ui.horizontalSlider.value()
        
        if value == 0:
            self.ui.label_6.setText("  Max Seashells: 0")
            self.max_seashells = 0
            self.excluded_checks.update(SEASHELL_REWARDS)
        elif value == 1:
            self.ui.label_6.setText("  Max Seashells: 5")
            self.max_seashells = 5
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
            self.excluded_checks.update(['15-seashell-reward', '30-seashell-reward', '40-seashell-reward', '50-seashell-reward'])
        elif value == 2:
            self.ui.label_6.setText("  Max Seashells: 15")
            self.max_seashells = 15
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
            self.excluded_checks.update(['30-seashell-reward', '40-seashell-reward', '50-seashell-reward'])
        elif value == 3:
            self.ui.label_6.setText("  Max Seashells: 30")
            self.max_seashells = 30
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
            self.excluded_checks.update(['40-seashell-reward', '50-seashell-reward'])
        elif value == 4:
            self.ui.label_6.setText("  Max Seashells: 40")
            self.max_seashells = 40
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
            self.excluded_checks.update(['50-seashell-reward'])
        else:
            self.ui.label_6.setText("  Max Seashells: 50")
            self.max_seashells = 50
            self.excluded_checks.difference_update(SEASHELL_REWARDS)
    
    
    
    # Update Logic
    def updateLogic(self):
        value = self.ui.horizontalSlider_2.value()

        if value == 0:
            self.ui.label_11.setText('  Logic:  Basic')
            self.logic = 'basic'
        elif value == 1:
            self.ui.label_11.setText('  Logic:  Advanced')
            self.logic = 'advanced'
        elif value == 2:
            self.ui.label_11.setText('  Logic:  Glitched')
            self.logic = 'glitched'
        elif value == 3:
            self.ui.label_11.setText('  Logic:  Death')
            self.logic = 'death'
        else:
            self.ui.label_11.setText('  Logic:  None')
            self.logic = 'none'



    # Randomize Button Clicked
    def randomizeButton_Clicked(self):
        
        if os.path.exists(self.ui.lineEdit.text()) and os.path.exists(self.ui.lineEdit_2.text()):
            
            # get needed params
            romPath = self.ui.lineEdit.text()
            
            seed = self.ui.lineEdit_3.text()
            if seed == "" or seed.lower() == "random":
                random.seed()
                seed = random.getrandbits(32)
            
            outdir = f"{self.ui.lineEdit_2.text()}/{seed}"
            
            settings = {
                'create-spoiler': self.ui.spoilerCheck.isChecked(),
                'free-book': self.ui.bookCheck.isChecked(),
                'unlocked-bombs': self.ui.unlockedBombsCheck.isChecked(),
                'shuffle-bombs': self.ui.shuffledBombsCheck.isChecked(),
                'fast-fishing': self.ui.fastFishingCheck.isChecked(),
                'fast-stealing': self.ui.stealingCheck.isChecked(),
                'fast-trendy': self.ui.fastTrendyCheck.isChecked(),
                'assured-sword-shield': self.ui.vanillaCheck.isChecked(),
                'reduce-farming': self.ui.farmingCheck.isChecked(),
                'shuffle-instruments': self.ui.instrumentCheck.isChecked(),
                'starting-instruments': self.ui.instrumentsComboBox.currentIndex(),
                'open-kanalet': self.ui.kanaletCheck.isChecked(),
                # 'fast-songs': self.ui.songsCheck.isChecked(),
                'shuffle-tunics': self.ui.tunicsCheck.isChecked(),
                'zap-sanity': self.ui.zapsCheck.isChecked(),
                'blup-sanity': self.ui.rupCheck.isChecked(),
                # 'randomize-entrances': self.ui.loadingCheck.isChecked(),
                'randomize-music': self.ui.musicCheck.isChecked(),
                'excluded-locations': self.excluded_checks
            }
            
            self.progress_window = ProgressWindow(romPath, outdir, seed, self.logic, ITEM_DEFS, LOGIC_DEFS, settings)
            self.progress_window.setFixedSize(472, 125)
            self.progress_window.setWindowTitle(f"{seed}")

            if self.mode == 'light':
                self.progress_window.setStyleSheet(LIGHT_STYLESHEET)
            else:
                self.progress_window.setStyleSheet(DARK_STYLESHEET)
            
            self.progress_window.show()
    
    
    
    # Tab changed
    def tab_Changed(self):
        
        if self.ui.tabWidget.currentIndex() == 1:
            
            self.ui.listWidget.clear()
            for check in TOTAL_CHECKS.difference(self.excluded_checks):
                self.ui.listWidget.addItem(self.checkToList(str(check)))
            
            self.ui.listWidget_2.clear()
            for check in self.excluded_checks:
                self.ui.listWidget_2.addItem(self.checkToList(str(check)))
    
    
    
    # Include Button Clicked
    def includeButton_Clicked(self):
        
        selectedItems = self.ui.listWidget_2.selectedItems()
        
        for i in selectedItems:
            self.ui.listWidget_2.takeItem(self.ui.listWidget_2.row(i))
            self.excluded_checks.remove(self.listToCheck(i.text()))
            self.ui.listWidget.addItem(i.text())
    
    
    
    # Exclude Button Clicked
    def excludeButton_Clicked(self):
        
        selectedItems = self.ui.listWidget.selectedItems()
        
        for i in selectedItems:
            self.ui.listWidget.takeItem(self.ui.listWidget.row(i))
            self.ui.listWidget_2.addItem(i.text())
            self.excluded_checks.add(self.listToCheck(i.text()))
    
    
    
    # some-check to Some Check
    def checkToList(self, check):
        s = sub("-", " ", check).title()
        return s
    
    
    
    # Some Check to some-check
    def listToCheck(self, check):
        
        stayUpper = ('d0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8')
        
        s = sub(" ", "-", check).lower()
        
        if s.startswith(stayUpper):
            s = s.replace('d', 'D', 1)
        
        return s



    # Override key press event to change theme
    def keyPressEvent(self, event):

        modifiers = QtWidgets.QApplication.keyboardModifiers()
        self._ctrl_is_active = modifiers == QtCore.Qt.KeyboardModifier.ControlModifier

        if event.key() == QtCore.Qt.Key.Key_L and self._ctrl_is_active:
            if self.mode == 'light':
                self.mode = str('dark')
                self.setStyleSheet(DARK_STYLESHEET)
                if self.ui.explainationLabel.text() == 'Hover over an option to see what it does':
                    self.ui.explainationLabel.setStyleSheet('color: rgb(175, 175, 175);')
                else:
                    self.ui.explainationLabel.setStyleSheet('color: white;')
            else:
                self.mode = str('light')
                self.setStyleSheet(LIGHT_STYLESHEET)
                if self.ui.explainationLabel.text() == 'Hover over an option to see what it does':
                    self.ui.explainationLabel.setStyleSheet('color: rgb(80, 80, 80);')
                else:
                    self.ui.explainationLabel.setStyleSheet('color: black;')
    


    # Override close event to save settings
    def closeEvent(self, event):
        self.saveSettings()
        event.accept()
