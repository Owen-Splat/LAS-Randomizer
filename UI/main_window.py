from PySide6 import QtCore, QtWidgets
from UI.ui_form import Ui_MainWindow
from UI.progress_window import ProgressWindow
from update import UpdateProcess
from randomizer_paths import IS_RUNNING_FROM_SOURCE
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
        self.excluded_checks = set()
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
        # self.ui.trendyCheck.clicked.connect(self.trendyCheck_Clicked)
        self.ui.giftsCheck.clicked.connect(self.giftsCheck_Clicked)
        self.ui.tradeGiftsCheck.clicked.connect(self.tradeQuest_Clicked)
        self.ui.bossCheck.clicked.connect(self.bossCheck_Clicked)
        self.ui.miscellaneousCheck.clicked.connect(self.miscellaneousCheck_Clicked)
        self.ui.heartsCheck.clicked.connect(self.heartsCheck_Clicked)
        self.ui.seashellsComboBox.currentIndexChanged.connect(self.updateSeashells)
        self.ui.leavesCheck.clicked.connect(self.leavesCheck_Clicked)
        # locations tab
        self.ui.tabWidget.currentChanged.connect(self.tab_Changed)
        self.ui.includeButton.clicked.connect(self.includeButton_Clicked)
        self.ui.excludeButton.clicked.connect(self.excludeButton_Clicked)
        
        ### DESCRIPTIONS
        self.descItems = self.ui.tab.findChildren(QtWidgets.QCheckBox)
        self.descItems.extend([self.ui.seashellsComboBox,
                                self.ui.tricksComboBox,
                                self.ui.instrumentsComboBox,
                                self.ui.owlsComboBox])
        for item in self.descItems:
            item.installEventFilter(self)
        
        ### show and check for updates
        self.setFixedSize(780, 640)
        self.setWindowTitle(f'{self.windowTitle()} v{VERSION}')
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
            self.ui.updateChecker.setText(f"<a href='{DOWNLOAD_PAGE}'>Update found!</a>")
        else:
            self.ui.updateChecker.setText('No updates available')
    
    
    
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
        # self.excluded_checks.update(TRENDY_REWARDS)

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
        self.ui.instrumentsComboBox.setCurrentIndex(0)

        self.ui.seashellsComboBox.setCurrentIndex(2)
        self.excluded_checks.difference_update(set(['5-seashell-reward', '15-seashell-reward']))
        self.excluded_checks.update(set(['30-seashell-reward', '40-seashell-reward', '50-seashell-reward']))

        self.ui.leavesCheck.setChecked(True)
        self.excluded_checks.difference_update(LEAF_LOCATIONS)

        self.ui.tricksComboBox.setCurrentIndex(0)

        self.ui.bookCheck.setChecked(True)
        self.ui.unlockedBombsCheck.setChecked(True)
        self.ui.shuffledBombsCheck.setChecked(False)
        self.ui.fastTrendyCheck.setChecked(False)
        self.ui.stealingCheck.setChecked(True)
        self.ui.farmingCheck.setChecked(True)
        self.ui.vanillaCheck.setChecked(True)
        self.ui.musicCheck.setChecked(False)
        self.ui.enemyCheck.setChecked(False)
        self.ui.spoilerCheck.setChecked(True)
        self.ui.kanaletCheck.setChecked(True)
        self.ui.tunicsCheck.setChecked(True)
        self.ui.trapsCheck.setChecked(False)
        self.ui.rupCheck.setChecked(False)
        self.ui.bridgeCheck.setChecked(True)
        self.ui.mazeCheck.setChecked(True)
        self.ui.swampCheck.setChecked(False)
        self.ui.fastMSCheck.setChecked(False)
        self.ui.chestSizesCheck.setChecked(False)
        self.ui.songsCheck.setChecked(False)
        self.ui.fastFishingCheck.setChecked(True)
        self.ui.owlsComboBox.setCurrentIndex(0)

        self.tab_Changed() # just call the same event as when changing the tab to refresh the list



    def saveSettings(self):
        settings_dict = {
            'Theme': self.mode,
            'Romfs_Folder': self.ui.lineEdit.text(),
            'Output_Folder': self.ui.lineEdit_2.text(),
            'Seed': self.ui.lineEdit_3.text(),
            'Logic': LOGIC_PRESETS[self.ui.tricksComboBox.currentIndex()],
            'Create_Spoiler': self.ui.spoilerCheck.isChecked(),
            'NonDungeon_Chests': self.ui.chestsCheck.isChecked(),
            'Fishing': self.ui.fishingCheck.isChecked(),
            'Rapids': self.ui.rapidsCheck.isChecked(),
            'Dampe': self.ui.dampeCheck.isChecked(),
            # 'Trendy': self.ui.trendyCheck.isChecked(),
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
            'Shuffled_Tunics': self.ui.tunicsCheck.isChecked(),
            'Fast_Fishing': self.ui.fastFishingCheck.isChecked(),
            'Fast_Stealing': self.ui.stealingCheck.isChecked(),
            'Fast_Trendy': self.ui.fastTrendyCheck.isChecked(),
            'Fast_Songs': self.ui.songsCheck.isChecked(),
            'Fast_Master_Stalfos': self.ui.fastMSCheck.isChecked(),
            'Scaled_Chest_Sizes': self.ui.chestSizesCheck.isChecked(),
            'Reduced_Farming': self.ui.farmingCheck.isChecked(),
            'Vanilla_Start': self.ui.vanillaCheck.isChecked(),
            'Open_Kanalet': self.ui.kanaletCheck.isChecked(),
            'Open_Bridge': self.ui.bridgeCheck.isChecked(),
            'Open_Mamu': self.ui.mazeCheck.isChecked(),
            'Trapsanity': self.ui.trapsCheck.isChecked(),
            'Blupsanity': self.ui.rupCheck.isChecked(),
            'Classic_D2': self.ui.swampCheck.isChecked(),
            'Owl_Statues': OWLS_SETTINGS[self.ui.owlsComboBox.currentIndex()],
            # 'Shuffled_Companions': self.ui.companionCheck.isChecked(),
            # 'Randomize_Entrances': self.ui.loadingCheck.isChecked(),
            'Randomize_Music': self.ui.musicCheck.isChecked(),
            'Randomize_Enemies': self.ui.enemyCheck.isChecked(),
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
        
        # # trendy
        # try:
        #     self.ui.trendyCheck.setChecked(SETTINGS['Trendy'])
        # except (KeyError, TypeError):
        #     self.ui.trendyCheck.setChecked(True)
        
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
        except (KeyError, TypeError, IndexError) as e:
            print(e.args)
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
            self.ui.fastMSCheck.setChecked(SETTINGS['Fast_Master_Stalfos'])
        except (KeyError, TypeError):
            self.ui.fastMSCheck.setChecked(False)
        
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
        
        # shuffled tunics
        try:
            self.ui.tunicsCheck.setChecked(SETTINGS['Shuffled_Tunics'])
        except (KeyError, TypeError):
            self.ui.tunicsCheck.setChecked(True)

        # trapsanity
        try:
            self.ui.trapsCheck.setChecked(SETTINGS['Trapsanity'])
        except (KeyError, TypeError):
            self.ui.trapsCheck.setChecked(False)
        
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
        
        # randomize enemies
        try:
            self.ui.enemyCheck.setChecked(SETTINGS['Randomize_Enemies'])
        except (KeyError, TypeError):
            self.ui.enemyCheck.setChecked(False)
        
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
            if not self.ui.heartsCheck.isChecked():
                self.excluded_checks.update(HEART_PIECE_LOCATIONS)
            if not self.ui.leavesCheck.isChecked():
                self.excluded_checks.update(LEAF_LOCATIONS)
            # if not self.ui.trendyCheck.isChecked():
            #     self.excluded_checks.update(TRENDY_REWARDS)


    
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
    
    
    
    # # Trendy Check Changed
    # def trendyCheck_Clicked(self):
    #     if self.ui.trendyCheck.isChecked():
    #         self.excluded_checks.difference_update(TRENDY_REWARDS)
    #     else:
    #         self.excluded_checks.update(TRENDY_REWARDS)



    # Gifts Check Changed
    def giftsCheck_Clicked(self):
        if self.ui.giftsCheck.isChecked():
            self.excluded_checks.difference_update(FREE_GIFT_LOCATIONS)
        else:
            self.excluded_checks.update(FREE_GIFT_LOCATIONS)
    
    
    
    # Trade Quest Check Changed
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
    


    def leavesCheck_Clicked(self):
        if self.ui.leavesCheck.isChecked():
            self.excluded_checks.difference_update(LEAF_LOCATIONS)
        else:
            self.excluded_checks.update(LEAF_LOCATIONS)
    


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



    # Randomize Button Clicked
    def randomizeButton_Clicked(self):
        
        if os.path.exists(self.ui.lineEdit.text()) and os.path.exists(self.ui.lineEdit_2.text()):
            
            # get needed params
            rom_path = self.ui.lineEdit.text()
            
            seed = self.ui.lineEdit_3.text()
            if seed == "" or seed.lower() == "random":
                random.seed()
                seed = str(random.getrandbits(32))
            
            outdir = f"{self.ui.lineEdit_2.text()}/{seed}"
            
            logic = LOGIC_PRESETS[self.ui.tricksComboBox.currentIndex()]

            settings = {
                'create-spoiler': self.ui.spoilerCheck.isChecked(),
                'free-book': self.ui.bookCheck.isChecked(),
                'unlocked-bombs': self.ui.unlockedBombsCheck.isChecked(),
                'shuffle-bombs': self.ui.shuffledBombsCheck.isChecked(),
                'reduce-farming': self.ui.farmingCheck.isChecked(),
                'assured-sword-shield': self.ui.vanillaCheck.isChecked(),
                'fast-fishing': self.ui.fastFishingCheck.isChecked(),
                'fast-stealing': self.ui.stealingCheck.isChecked(),
                'fast-trendy': self.ui.fastTrendyCheck.isChecked(),
                'fast-songs': self.ui.songsCheck.isChecked(),
                'shuffle-instruments': self.ui.instrumentCheck.isChecked(),
                'starting-instruments': self.ui.instrumentsComboBox.currentIndex(),
                'shuffle-tunics': self.ui.tunicsCheck.isChecked(),
                'open-kanalet': self.ui.kanaletCheck.isChecked(),
                'open-bridge': self.ui.bridgeCheck.isChecked(),
                'open-mamu': self.ui.mazeCheck.isChecked(),
                'trap-sanity': self.ui.trapsCheck.isChecked(),
                'blup-sanity': self.ui.rupCheck.isChecked(),
                'classic-d2': self.ui.swampCheck.isChecked(),
                'owl-overworld-gifts': True if OWLS_SETTINGS[self.ui.owlsComboBox.currentIndex()] in ('overworld', 'all') else False,
                'owl-dungeon-gifts': True if OWLS_SETTINGS[self.ui.owlsComboBox.currentIndex()] in ('dungeons', 'all') else False,
                # 'owl-hints': True if OWLS_SETTINGS[self.ui.owlsComboBox.currentIndex()] in ['hints', 'hybrid'] else False,
                'fast-master-stalfos': self.ui.fastMSCheck.isChecked(),
                'scaled-chest-sizes': self.ui.chestSizesCheck.isChecked(),
                # 'shuffle-companions': self.ui.companionCheck.isChecked(),
                'seashells-important': True if len([s for s in SEASHELL_REWARDS if s not in self.excluded_checks]) > 0 else False,
                # 'randomize-entrances': self.ui.loadingCheck.isChecked(),
                'randomize-music': self.ui.musicCheck.isChecked(),
                'randomize-enemies': self.ui.enemyCheck.isChecked(),
                'panel-enemies': True if len([s for s in DAMPE_REWARDS if s not in self.excluded_checks]) > 0 else False,
                'excluded-locations': self.excluded_checks
            }
            
            self.progress_window = ProgressWindow(rom_path, outdir, seed, logic, ITEM_DEFS, LOGIC_DEFS, settings)
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
        for i in self.ui.listWidget_2.selectedItems():
            self.ui.listWidget_2.takeItem(self.ui.listWidget_2.row(i))
            self.excluded_checks.remove(self.listToCheck(i.text()))
            self.ui.listWidget.addItem(i.text())
    
    
    
    # Exclude Button Clicked
    def excludeButton_Clicked(self):
        for i in self.ui.listWidget.selectedItems():
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
