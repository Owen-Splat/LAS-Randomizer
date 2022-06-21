#!/usr/bin/env python3

from PySide6 import QtCore, QtGui, QtWidgets
from UI.form import Ui_MainWindow
from progress_window import ProgressWindow
from update import UpdateProcess
from randomizer_paths import ROOT_PATH, DATA_PATH, RESOURCE_PATH

import qdarktheme

import yaml
from indentation import MyDumper

import sys
import os
import random
from re import sub



LIGHT_STYLESHEET = qdarktheme.load_stylesheet('light')
DARK_STYLESHEET = qdarktheme.load_stylesheet('dark')

with open(os.path.join(DATA_PATH, 'items.yml'), 'r') as f:
    ITEM_DEFS = yaml.safe_load(f)

with open(os.path.join(DATA_PATH, 'logic.yml'), 'r') as f:
    LOGIC_DEFS = yaml.safe_load(f)
    TRICKS = list(filter(lambda x: LOGIC_DEFS[x]['type'] == 'trick', LOGIC_DEFS))

with open(os.path.join(DATA_PATH, 'locations.yml'), 'r') as f:
    LOCATIONS = yaml.safe_load(f)

with open(os.path.join(DATA_PATH, 'seeds.yml'), 'r') as f:
    seeds = yaml.safe_load(f)
    ADJECTIVES = seeds['Adjectives']
    CHARACTERS = seeds['Characters']

try:
    with open('settings.yaml', 'r') as settingsFile:
        SETTINGS = yaml.safe_load(settingsFile)
        DEFAULTS = False
except FileNotFoundError:
    DEFAULTS = True


# game locations
MISCELLANEOUS_CHESTS = LOCATIONS['Chest_Locations']
FAST_FISHING_REWARDS = LOCATIONS['Fast_Fishing_Rewards']
OTHER_FISHING_REWARDS = LOCATIONS['Other_Fishing_Rewards']
RAPIDS_REWARDS = LOCATIONS['Rapids_Rewards']
DAMPE_REWARDS = LOCATIONS['Dampe_Rewards']
FREE_GIFT_LOCATIONS = LOCATIONS['Free_Gifts']
TRADE_GIFT_LOCATIONS = LOCATIONS['Trade_Gifts']
BOSS_LOCATIONS = LOCATIONS['Boss_Locations']
MISC_LOCATIONS = LOCATIONS['Misc_Items']
SEASHELL_REWARDS = LOCATIONS['Mansion']
TRENDY_REWARDS = LOCATIONS['Trendy_Rewards']
HEART_PIECE_LOCATIONS = LOCATIONS['Heart_Pieces']

# keep track of all game locations
TOTAL_CHECKS = set(MISCELLANEOUS_CHESTS)
TOTAL_CHECKS.update(FAST_FISHING_REWARDS)
TOTAL_CHECKS.update(OTHER_FISHING_REWARDS)
TOTAL_CHECKS.update(RAPIDS_REWARDS)
TOTAL_CHECKS.update(DAMPE_REWARDS)
TOTAL_CHECKS.update(FREE_GIFT_LOCATIONS)
TOTAL_CHECKS.update(TRADE_GIFT_LOCATIONS)
TOTAL_CHECKS.update(BOSS_LOCATIONS)
TOTAL_CHECKS.update(MISC_LOCATIONS)
TOTAL_CHECKS.update(SEASHELL_REWARDS)
TOTAL_CHECKS.update(TRENDY_REWARDS)
TOTAL_CHECKS.update(HEART_PIECE_LOCATIONS)



class MainWindow(QtWidgets.QMainWindow):
    
    def __init__(self):
        super (MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Styling
        for b in self.findChildren(QtWidgets.QPushButton):
            b.setStyleSheet("QPushButton {background-color: rgb(218, 218, 218)}"
                            "QPushButton {border: 1px solid black}"
                            "QPushButton {color: rgb(0, 0, 0)}"
                            "QPushButton:hover {background-color: rgb(200, 200, 200)}"
                            "QPushButton:pressed {background-color: rgb(175, 175, 175)}")
        

        # Keep track of stuff
        self.maxSeashells = int(15)
        self.excludedChecks = set()
        self.logic = str('basic')
        self.mode = str('dark')


        # Load User Settings
        if not DEFAULTS:
            self.LoadSettings()
        else:
            self.ApplyDefaults()
        
        if self.mode == 'light':
            self.setStyleSheet(qdarktheme.load_stylesheet('light'))
            self.ui.explainationLabel.setStyleSheet('color: rgb(80, 80, 80);')
        else:
            self.setStyleSheet(qdarktheme.load_stylesheet('dark'))
            self.ui.explainationLabel.setStyleSheet('color: rgb(175, 175, 175);')


        ### SUBSCRIBE TO EVENTS
        
        # folder browsing, seed generation, and randomize button
        self.ui.browseButton1.clicked.connect(self.RomBrowse)
        self.ui.browseButton2.clicked.connect(self.OutBrowse)
        self.ui.seedButton.clicked.connect(self.GenerateSeed)
        self.ui.randomizeButton.clicked.connect(self.RandomizeButton_Clicked)
        self.ui.resetButton.clicked.connect(self.ApplyDefaults)
        # progress checks
        self.ui.chestsCheck.clicked.connect(self.ChestsCheck_Clicked)
        self.ui.fishingCheck.clicked.connect(self.FishingCheck_Clicked)
        self.ui.rapidsCheck.clicked.connect(self.RapidsCheck_Clicked)
        self.ui.dampeCheck.clicked.connect(self.DampeCheck_Clicked)
        self.ui.giftsCheck.clicked.connect(self.GiftsCheck_Clicked)
        self.ui.tradeGiftsCheck.clicked.connect(self.tradeQuest_Clicked)
        self.ui.bossCheck.clicked.connect(self.BossCheck_Clicked)
        self.ui.miscellaneousCheck.clicked.connect(self.MiscellaneousCheck_Clicked)
        self.ui.heartsCheck.clicked.connect(self.HeartsCheck_Clicked)
        self.ui.horizontalSlider.valueChanged.connect(self.UpdateSeashells)
        self.ui.horizontalSlider_2.valueChanged.connect(self.UpdateLogic)
        # extra options
        self.ui.lessFishingCheck.clicked.connect(self.FastFishing_Clicked)
        # tab 2
        self.ui.tabWidget.currentChanged.connect(self.Tab_Changed)
        self.ui.includeButton.clicked.connect(self.IncludeButton_Clicked)
        self.ui.excludeButton.clicked.connect(self.ExcludeButton_Clicked)
        
        
        ### DESCRIPTIONS
        self.checkBoxes = self.ui.tab.findChildren(QtWidgets.QCheckBox)
        self.checkBoxes.extend([self.ui.label_6, self.ui.horizontalSlider])
        for check in self.checkBoxes:
            check.installEventFilter(self)
    
    
    
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
    
    
    
    ### UPDATE CHECKER
    def showEvent(self, event):
        
        self.process = UpdateProcess() # initialize a new QThread class
        self.process.canUpdate.connect(self.ShowUpdate) # connect a boolean signal to ShowUpdate()
        self.process.start() # start the thread
        event.accept()
    
    
    
    # show update if there is one
    def ShowUpdate(self, update):
        
        if update:
            self.ui.updateChecker.setText("<a href='https://github.com/OSmart32/LASR-App-Python/releases/latest'>Update found!</a>")
        else:
            self.ui.updateChecker.setText('No update available.')
    
    
    
    ### STORED SETTINGS
    # apply stored settings or defaults
    def LoadSettings(self):
        
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
            if not checked:
                self.ui.lessFishingCheck.setEnabled(False)
                self.ui.lessFishingCheck.setStyleSheet(".QCheckBox {text-decoration: line-through}")
        except (KeyError, TypeError):
            self.ui.fishingCheck.setChecked(True)
        
        # less fishing
        try:
            self.ui.lessFishingCheck.setChecked(SETTINGS['Less-Fishing'])
        except (KeyError, TypeError):
            self.ui.lessFishingCheck.setChecked(True)
        
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
        
        # seashells
        try:
            num = SETTINGS['Seashells']
            if num == 0:
                self.maxSeashells = 0
                self.ui.horizontalSlider.setValue(0)
                self.ui.label_6.setText("  Max Seashells: {}".format(self.maxSeashells))
            elif num == 5:
                self.maxSeashells = 5
                self.ui.horizontalSlider.setValue(1)
                self.ui.label_6.setText("  Max Seashells: {}".format(self.maxSeashells))
            elif num == 15:
                self.maxSeashells = 15
                self.ui.horizontalSlider.setValue(2)
                self.ui.label_6.setText("  Max Seashells: {}".format(self.maxSeashells))
            elif num == 30:
                self.maxSeashells = 30
                self.ui.horizontalSlider.setValue(3)
                self.ui.label_6.setText("  Max Seashells: {}".format(self.maxSeashells))
            elif num == 40:
                self.maxSeashells = 40
                self.ui.horizontalSlider.setValue(4)
                self.ui.label_6.setText("  Max Seashells: {}".format(self.maxSeashells))
            elif num == 50:
                self.maxSeashells = 50
                self.ui.horizontalSlider.setValue(5)
                self.ui.label_6.setText("  Max Seashells: {}".format(self.maxSeashells))
            else:
                self.maxSeashells = 15
                self.ui.horizontalSlider.setValue(2)
                self.ui.label_6.setText("  Max Seashells: {}".format(self.maxSeashells))
        except (KeyError, TypeError):
            self.maxSeashells = 15
            self.ui.horizontalSlider.setValue(2)
            self.ui.label_6.setText("  Max Seashells: {}".format(self.maxSeashells))
        
        # logic
        try:
            logic = str(SETTINGS['Logic'].lower())
            if logic in ['basic, advanced', 'glitched', 'none']:
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
                else:
                    self.ui.horizontalSlider_2.setValue(3)
                    self.ui.label_11.setText('  Logic:  None')
            else:
                self.logic = 'Basic'
                self.ui.horizontalSlider_2.setValue(0)
                self.ui.label_11.setText('  Logic:  Basic')
        except (KeyError, TypeError):
            self.logic = 'Basic'
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
            self.ui.trendyCheck.setChecked(SETTINGS['Fast_Trendy'])
        except (KeyError, TypeError):
            self.ui.trendyCheck.setChecked(False)
        
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
            self.ui.zapsCheck.setChecked(SETTINGS['Zap_Sanity'])
        except (KeyError, TypeError):
            self.ui.zapsCheck.setChecked(False)

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

        # # blue removal
        # try:
        #     self.ui.blurCheck.setChecked(SETTINGS['Blur_Removal'])
        # except (KeyError, TypeError):
        #     self.ui.blurCheck.setChecked(True)

        # spoiler log
        try:
            self.ui.spoilerCheck.setChecked(SETTINGS['Create_Spoiler'])
        except (KeyError, TypeError):
            self.ui.spoilerCheck.setChecked(True)
        
        # excluded checks
        try:
            for check in SETTINGS['Excluded_Locations']:
                if check in TOTAL_CHECKS:
                    self.excludedChecks.add(check)
        except (KeyError, TypeError):
            if not self.ui.chestsCheck.isChecked():
                self.excludedChecks.update(MISCELLANEOUS_CHESTS)
            if not self.ui.fishingCheck.isChecked():
                self.excludedChecks.update(FAST_FISHING_REWARDS)
                self.excludedChecks.update(OTHER_FISHING_REWARDS)
            if not self.ui.rapidsCheck.isChecked():
                self.excludedChecks.update(RAPIDS_REWARDS)
            if not self.ui.dampeCheck.isChecked():
                self.excludedChecks.update(DAMPE_REWARDS)
            if not self.ui.giftsCheck.isChecked():
                self.excludedChecks.update(FREE_GIFT_LOCATIONS)
            if not self.ui.tradeGiftsCheck.isChecked():
                self.excludedChecks.update(TRADE_GIFT_LOCATIONS)
            if not self.ui.bossCheck.isChecked():
                self.excludedChecks.update(BOSS_LOCATIONS)
            if not self.ui.miscellaneousCheck.isChecked():
                self.excludedChecks.update(MISC_LOCATIONS)
            if not self.ui.trendyCheck.isChecked():
                self.excludedChecks.update(TRENDY_REWARDS)
            self.excludedChecks.update(TRADE_GIFT_LOCATIONS)
    
    
    
    # apply defaults
    def ApplyDefaults(self):
        
        self.ui.chestsCheck.setChecked(True)
        self.excludedChecks.difference_update(MISCELLANEOUS_CHESTS)
        
        self.ui.fishingCheck.setChecked(True)
        self.ui.lessFishingCheck.setEnabled(True)
        self.ui.lessFishingCheck.setStyleSheet("")
        self.ui.lessFishingCheck.setChecked(True)
        self.excludedChecks.difference_update(FAST_FISHING_REWARDS)
        self.excludedChecks.update(OTHER_FISHING_REWARDS)

        self.ui.rapidsCheck.setChecked(False)
        self.excludedChecks.update(RAPIDS_REWARDS)

        self.ui.dampeCheck.setChecked(False)
        self.excludedChecks.update(DAMPE_REWARDS)

        self.ui.giftsCheck.setChecked(True)
        self.excludedChecks.difference_update(FREE_GIFT_LOCATIONS)
        
        self.ui.tradeGiftsCheck.setChecked(False)
        self.excludedChecks.update(TRADE_GIFT_LOCATIONS)

        self.ui.bossCheck.setChecked(True)
        self.excludedChecks.difference_update(BOSS_LOCATIONS)
        
        self.ui.miscellaneousCheck.setChecked(True)
        self.excludedChecks.difference_update(MISC_LOCATIONS)
        
        self.ui.heartsCheck.setChecked(True)
        self.excludedChecks.difference_update(HEART_PIECE_LOCATIONS)

        self.ui.instrumentCheck.setChecked(True)
        
        self.ui.label_6.setText("  Max Seashells: 15")
        self.ui.horizontalSlider.setValue(2)
        self.maxSeashells = 15
        self.excludedChecks.difference_update(set(['5-seashell-reward', '15-seashell-reward']))
        self.excludedChecks.update(set(['30-seashell-reward', '40-seashell-reward', '50-seashell-reward']))

        self.ui.label_11.setText('  Logic:  Basic')
        self.ui.horizontalSlider_2.setValue(0)
        self.logic = 'Basic'

        self.ui.bookCheck.setChecked(True)
        self.ui.unlockedBombsCheck.setChecked(True)
        self.ui.shuffledBombsCheck.setChecked(False)
        self.ui.trendyCheck.setChecked(False)
        self.excludedChecks.update(TRENDY_REWARDS)
        self.ui.stealingCheck.setChecked(True)
        self.ui.farmingCheck.setChecked(True)
        self.ui.vanillaCheck.setChecked(True)
        self.ui.musicCheck.setChecked(False)
        self.ui.spoilerCheck.setChecked(True)
        self.ui.kanaletCheck.setChecked(True)
        self.ui.tunicsCheck.setChecked(True)
        self.ui.zapsCheck.setChecked(False)

        self.excludedChecks.update(TRADE_GIFT_LOCATIONS)
        # self.excludedChecks.add('rapids-middle-island')
        
        self.Tab_Changed() # just call the same event as when changing the tab to refresh the list
    
    
    
    # save settings to file
    def SaveSettings(self):
        
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
            'Seashells': self.maxSeashells,
            'Free_Book': self.ui.bookCheck.isChecked(),
            'Unlocked_Bombs': self.ui.unlockedBombsCheck.isChecked(),
            'Shuffled_Bombs': self.ui.shuffledBombsCheck.isChecked(),
            'Fast_Trendy': self.ui.trendyCheck.isChecked(),
            'Fast_Stealing': self.ui.stealingCheck.isChecked(),
            'Reduced_Farming': self.ui.farmingCheck.isChecked(),
            'Vanilla_Start': self.ui.vanillaCheck.isChecked(),
            'Less_Fishing': self.ui.lessFishingCheck.isChecked(),
            'Open_Kanalet': self.ui.kanaletCheck.isChecked(),
            # 'Fast_Songs': self.ui.songsCheck.isChecked(),
            'Shuffled_Tunics': self.ui.tunicsCheck.isChecked(),
            'Zap_Sanity': self.ui.zapsCheck.isChecked(),
            # 'Randomize_Entrances': self.ui.loadingCheck.isChecked(),
            'Randomize_Music': self.ui.musicCheck.isChecked(),
            # 'Blur_Removal': self.ui.blurCheck.isChecked(),
            'Excluded_Locations': list(self.excludedChecks)
        }
        
        with open('settings.yaml', 'w') as settingsFile:
            yaml.dump(settings_dict, settingsFile, Dumper=MyDumper, sort_keys=False)
    
    
    
    ###############################################################################################################################
    # RomFS Folder Browse
    def RomBrowse(self):
        
        folderpath = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
        
        if folderpath != "":
            self.ui.lineEdit.setText(folderpath)
    
    
    
    # Output Folder Browse
    def OutBrowse(self):
        
        folderpath = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
        
        if folderpath != "":
            self.ui.lineEdit_2.setText(folderpath)
    
    
    
    # Generate New Seed
    def GenerateSeed(self):
        
        adj1 = random.choice(ADJECTIVES)
        adj2 = random.choice(ADJECTIVES)
        char = random.choice(CHARACTERS)
        
        self.ui.lineEdit_3.setText(adj1 + adj2 + char)
    
    
    
    # Chests Check Changed
    def ChestsCheck_Clicked(self):

        if self.ui.chestsCheck.isChecked():
            self.excludedChecks.difference_update(MISCELLANEOUS_CHESTS)
        else:
            self.excludedChecks.update(MISCELLANEOUS_CHESTS)
    
    
    
    # Fishing Check Changed
    def FishingCheck_Clicked(self):
        
        if self.ui.fishingCheck.isChecked():
            self.excludedChecks.difference_update(FAST_FISHING_REWARDS)
            
            if not self.ui.lessFishingCheck.isChecked():
                self.excludedChecks.difference_update(OTHER_FISHING_REWARDS)
            
            self.ui.lessFishingCheck.setEnabled(True)
            self.ui.lessFishingCheck.setStyleSheet("")
        else:
            self.excludedChecks.update(FAST_FISHING_REWARDS)
            self.excludedChecks.update(OTHER_FISHING_REWARDS)
            self.ui.lessFishingCheck.setEnabled(False)
            self.ui.lessFishingCheck.setStyleSheet(".QCheckBox {text-decoration: line-through}")
    
    
    
    # Fast Fishing Check Changed
    def FastFishing_Clicked(self):
        
        if self.ui.lessFishingCheck.isChecked():
            self.excludedChecks.update(OTHER_FISHING_REWARDS)
        else:
            self.excludedChecks.difference_update(OTHER_FISHING_REWARDS)
    
    
    
    # Rapids Check Changed
    def RapidsCheck_Clicked(self):
        
        if self.ui.rapidsCheck.isChecked():
            self.excludedChecks.difference_update(RAPIDS_REWARDS)
        else:
            self.excludedChecks.update(RAPIDS_REWARDS)
    
    
    
    # Dampe Check Changed
    def DampeCheck_Clicked(self):
        
        if self.ui.dampeCheck.isChecked():
            self.excludedChecks.difference_update(DAMPE_REWARDS)
        else:
            self.excludedChecks.update(DAMPE_REWARDS)
    
    
    
    # Gifts Check Changed
    def GiftsCheck_Clicked(self):
        
        if self.ui.giftsCheck.isChecked():
            self.excludedChecks.difference_update(FREE_GIFT_LOCATIONS)
        else:
            self.excludedChecks.update(FREE_GIFT_LOCATIONS)
    
    
    
    # Lens Check Changed
    def tradeQuest_Clicked(self):
        
        if self.ui.tradeGiftsCheck.isChecked():
            self.excludedChecks.difference_update(TRADE_GIFT_LOCATIONS)
        else:
            self.excludedChecks.update(TRADE_GIFT_LOCATIONS)
    
    
    
    # Bosses Check Changed
    def BossCheck_Clicked(self):
        
        if self.ui.bossCheck.isChecked():
            self.excludedChecks.difference_update(BOSS_LOCATIONS)
        else:
            self.excludedChecks.update(BOSS_LOCATIONS)
    
    
    
    # Miscellaneous Standing Items Check Changed
    def MiscellaneousCheck_Clicked(self):
        
        if self.ui.miscellaneousCheck.isChecked():
            self.excludedChecks.difference_update(MISC_LOCATIONS)
        else:
            self.excludedChecks.update(MISC_LOCATIONS)
    
    
    
    # Heart Pieces Check Changed
    def HeartsCheck_Clicked(self):
        
        if self.ui.heartsCheck.isChecked():
            self.excludedChecks.difference_update(HEART_PIECE_LOCATIONS)
        else:
            self.excludedChecks.update(HEART_PIECE_LOCATIONS)



    # Update Number of Max Seashells
    def UpdateSeashells(self):
        
        value = self.ui.horizontalSlider.value()
        
        if value == 0:
            self.ui.label_6.setText("  Max Seashells: 0")
            self.maxSeashells = 0
            self.excludedChecks.update(SEASHELL_REWARDS)
        
        elif value == 1:
            self.ui.label_6.setText("  Max Seashells: 5")
            self.maxSeashells = 5
            self.excludedChecks.difference_update(SEASHELL_REWARDS)
            self.excludedChecks.update(['15-seashell-reward', '30-seashell-reward', '40-seashell-reward', '50-seashell-reward'])
        
        elif value == 2:
            self.ui.label_6.setText("  Max Seashells: 15")
            self.maxSeashells = 15
            self.excludedChecks.difference_update(SEASHELL_REWARDS)
            self.excludedChecks.update(['30-seashell-reward', '40-seashell-reward', '50-seashell-reward'])
        
        elif value == 3:
            self.ui.label_6.setText("  Max Seashells: 30")
            self.maxSeashells = 30
            self.excludedChecks.difference_update(SEASHELL_REWARDS)
            self.excludedChecks.update(['40-seashell-reward', '50-seashell-reward'])
        
        elif value == 4:
            self.ui.label_6.setText("  Max Seashells: 40")
            self.maxSeashells = 40
            self.excludedChecks.difference_update(SEASHELL_REWARDS)
            self.excludedChecks.update(['50-seashell-reward'])
        
        else:
            self.ui.label_6.setText("  Max Seashells: 50")
            self.maxSeashells = 50
            self.excludedChecks.difference_update(SEASHELL_REWARDS)
        
    
    
    # Update Logic
    def UpdateLogic(self):

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
        
        else:
            self.ui.label_11.setText('  Logic:  None')
            self.logic = 'none'



    # Randomize Button Clicked
    def RandomizeButton_Clicked(self):
        
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
                'fast-trendy': self.ui.trendyCheck.isChecked(),
                'fast-stealing': self.ui.stealingCheck.isChecked(),
                'assured-sword-shield': self.ui.vanillaCheck.isChecked(),
                'reduce-farming': self.ui.farmingCheck.isChecked(),
                'shuffle-instruments': self.ui.instrumentCheck.isChecked(),
                'open-kanalet': self.ui.kanaletCheck.isChecked(),
                # 'fast-songs': self.ui.songsCheck.isChecked(),
                'shuffle-tunics': self.ui.tunicsCheck.isChecked(),
                'zap-sanity': self.ui.zapsCheck.isChecked(),
                # 'randomize-entrances': self.ui.loadingCheck.isChecked(),
                'randomize-music': self.ui.musicCheck.isChecked(),
                # 'blur-removal': self.ui.blurCheck.isChecked(),
                'excluded-locations': self.excludedChecks
            }
            
            self.progress_window = ProgressWindow(romPath, outdir, seed, ITEM_DEFS, LOGIC_DEFS, settings)
            self.progress_window.setFixedSize(472, 125)
            self.progress_window.setWindowTitle(f"{seed}")

            if self.mode == 'light':
                self.progress_window.setStyleSheet(LIGHT_STYLESHEET)
            else:
                self.progress_window.setStyleSheet(DARK_STYLESHEET)
            
            self.progress_window.show()
    
    
    
    # Tab changed
    def Tab_Changed(self):
        
        if self.ui.tabWidget.currentIndex() == 1:
            
            self.ui.listWidget.clear()
            for check in TOTAL_CHECKS.difference(self.excludedChecks):
                self.ui.listWidget.addItem(self.CheckToList(str(check)))
            
            self.ui.listWidget_2.clear()
            for check in self.excludedChecks:
                self.ui.listWidget_2.addItem(self.CheckToList(str(check)))
    
    
    
    # Include Button Clicked
    def IncludeButton_Clicked(self):
        
        selectedItems = self.ui.listWidget_2.selectedItems()
        
        for i in selectedItems:
            self.ui.listWidget_2.takeItem(self.ui.listWidget_2.row(i))
            self.excludedChecks.remove(self.ListToCheck(i.text()))
            self.ui.listWidget.addItem(i.text())
    
    
    
    # Exclude Button Clicked
    def ExcludeButton_Clicked(self):
        
        selectedItems = self.ui.listWidget.selectedItems()
        
        for i in selectedItems:
            self.ui.listWidget.takeItem(self.ui.listWidget.row(i))
            self.ui.listWidget_2.addItem(i.text())
            self.excludedChecks.add(self.ListToCheck(i.text()))
    
    
    
    # some-check to Some Check
    def CheckToList(self, check):
        s = sub("-", " ", check).title()
        return s
    
    
    
    # Some Check to some-check
    def ListToCheck(self, check):
        
        stayUpper = ['d0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8']
        
        s = sub(" ", "-", check).lower()
        
        if s.startswith(tuple(stayUpper)):
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
        self.SaveSettings()
        event.accept()





#######################################################################################################
def main():
    
    try:
        from sys import _MEIPASS
    except ImportError:
        import ctypes
        try:
            # Need to set app id so windows will display the custom taskbar icon while running from source
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Link's_Awakening_Switch_Randomizer")
        except AttributeError:
            pass
    
    app = QtWidgets.QApplication([])
    app.setStyle('Fusion')
    
    icon = QtGui.QIcon()
    icon.addPixmap(QtGui.QPixmap(os.path.join(RESOURCE_PATH, 'LASR_Icon.png')), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
    app.setWindowIcon(icon)
    
    m = MainWindow()
    m.setFixedSize(780, 639)
    m.show()
    
    sys.exit(app.exec())



if __name__ == '__main__':
    main()