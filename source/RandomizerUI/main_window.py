from PySide6 import QtCore, QtWidgets, QtGui
from RandomizerUI.UI.ui_form import Ui_MainWindow
from RandomizerUI.progress_window import ProgressWindow
from RandomizerUI.update import UpdateProcess, LogicUpdateProcess
from RandomizerCore.randomizer_data import *
from re import sub

import os
import yaml
import random
import string
import RandomizerUI.settings_manager as settings_manager



class MainWindow(QtWidgets.QMainWindow):
    
    def __init__(self):
        super (MainWindow, self).__init__()
        # self.trans = QtCore.QTranslator(self)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.includeButton_2.setVisible(False)
        self.ui.excludeButton_2.setVisible(False)
        self.current_option = ''
        self.clipboard = QtGui.QClipboard()
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
        self.applyDefaults()
        if not DEFAULTS:
            settings_manager.loadSettings(self)

        self.updateOwls()
        self.updateSeashells()

        if self.mode == 'light':
            self.setStyleSheet(LIGHT_STYLESHEET)
            self.ui.explainationLabel.setStyleSheet('color: rgb(80, 80, 80);')
        else:
            self.setStyleSheet(DARK_STYLESHEET)
            self.ui.explainationLabel.setStyleSheet('color: rgb(175, 175, 175);')
        
        ### SUBSCRIBE TO EVENTS
        self.ui.actionLight.triggered.connect(self.setLightMode)
        self.ui.actionDark.triggered.connect(self.setDarkMode)
        self.ui.actionChangelog.triggered.connect(self.showChangelog)
        self.ui.actionKnown_Issues.triggered.connect(self.showIssues)
        self.ui.actionHelpful_Tips.triggered.connect(self.showTips)
        self.ui.actionHelp.triggered.connect(self.showInfo)
        self.ui.browseButton1.clicked.connect(self.romBrowse)
        self.ui.browseButton2.clicked.connect(self.outBrowse)
        self.ui.seedButton.clicked.connect(self.generateSeed)
        self.ui.lineEdit_3.textChanged.connect(self.updateSettingsString)
        self.ui.randomizeButton.clicked.connect(self.randomizeButton_Clicked)
        self.ui.resetButton.clicked.connect(self.applyDefaults)
        self.ui.copyButton.clicked.connect(lambda x: self.clipboard.setText(self.ui.lineEdit_4.text()))
        self.ui.pasteButton.clicked.connect(self.pasteSettingsString)
        self.ui.randomizeSettingsButton.clicked.connect(self.randomizeSettings)
        self.ui.seashellsComboBox.currentIndexChanged.connect(self.updateSeashells)
        self.ui.owlsComboBox.currentIndexChanged.connect(self.updateOwls)
        self.ui.trapsComboBox.currentIndexChanged.connect(self.updateSettingsString)
        self.ui.instrumentsComboBox.currentIndexChanged.connect(self.updateSettingsString)
        self.ui.tricksComboBox.currentIndexChanged.connect(self.updateSettingsString)
        self.ui.stealingComboBox.currentIndexChanged.connect(self.updateSettingsString)
        self.ui.chestAspectComboBox.currentIndexChanged.connect(self.updateSettingsString)
        self.ui.rupeesSpinBox.valueChanged.connect(self.updateSettingsString)
        self.ui.tabWidget.currentChanged.connect(self.tab_Changed)
        self.ui.includeButton.clicked.connect(self.includeButton_Clicked)
        self.ui.excludeButton.clicked.connect(self.excludeButton_Clicked)
        self.ui.includeButton_3.clicked.connect(self.includeButton_3_Clicked)
        self.ui.excludeButton_3.clicked.connect(self.excludeButton_3_Clicked)
        # self.ui.includeButton_2.clicked.connect(self.includeButton_2_Clicked)
        # self.ui.excludeButton_2.clicked.connect(self.excludeButton_2_Clicked)

        for option in settings_manager.BASE_OPTIONS:
            widget = self.findChild(QtWidgets.QWidget, option)
            if widget is None:
                continue
            if isinstance(widget, QtWidgets.QCheckBox):
                widget.clicked.connect(self.checkClicked)
                widget.installEventFilter(self)

        ### DESCRIPTIONS
        desc_items = [
            self.ui.seashellsComboBox,
            self.ui.tricksComboBox,
            self.ui.instrumentsComboBox,
            self.ui.owlsComboBox,
            self.ui.platformComboBox,
            self.ui.rupeesSpinBox,
            self.ui.trapsComboBox,
            self.ui.chestAspectComboBox,
            self.ui.dungeonItemsComboBox,
            self.ui.stealingComboBox
        ]
        for item in desc_items:
            item.installEventFilter(self)
        
        self.makeSmartComboBoxes()

        self.setFixedSize(780, 650)
        self.setWindowTitle(f'{self.windowTitle()} v{VERSION}')
        # self.ui.retranslateUi(self)

        center = QtGui.QScreen.availableGeometry(QtWidgets.QApplication.primaryScreen()).center()
        geo = self.frameGeometry()
        geo.moveCenter(center)
        self.move(geo.topLeft())
        
        self.process = UpdateProcess()
        self.process.can_update.connect(self.showUpdate)
        self.process.give_version.connect(self.obtainVersion)
        self.process.start()
        
        self.show()


    def applyDefaults(self):
        settings_manager.applyDefaults(self)


    def updateSettingsString(self):
        self.ui.lineEdit_4.setText(settings_manager.encodeSettings(self))


    def makeSmartComboBoxes(self):
        combos = [
            self.ui.seashellsComboBox,
            self.ui.tricksComboBox,
            self.ui.instrumentsComboBox,
            self.ui.owlsComboBox,
            self.ui.platformComboBox,
            self.ui.trapsComboBox,
            self.ui.chestAspectComboBox,
            self.ui.dungeonItemsComboBox
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
            self.current_option = source.objectName()
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
    

    def romBrowse(self):
        folder_path = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
        if os.path.exists(folder_path):
            self.ui.lineEdit.setText(folder_path)
    
    
    def outBrowse(self):
        folder_path = QtWidgets.QFileDialog.getExistingDirectory(self, 'Select Folder')
        if os.path.exists(folder_path):
            self.ui.lineEdit_2.setText(folder_path)
    

    def generateSeed(self):
        adj1 = random.choice(ADJECTIVES)
        adj2 = random.choice(ADJECTIVES)
        char = random.choice(CHARACTERS)
        self.ui.lineEdit_3.setText(adj1 + adj2 + char)
    
    
    def checkClicked(self, checked):
        if self.current_option not in settings_manager.CHECK_LOCATIONS:
            return

        if self.current_option == 'rapidsCheck':
            if checked:
                self.excluded_checks.difference_update(RAPIDS_REWARDS)
                self.excluded_checks.difference_update(['owl-statue-rapids'])
            else:
                self.excluded_checks.update(RAPIDS_REWARDS)
                if self.overworld_owls:
                    self.excluded_checks.update(['owl-statue-rapids'])
        elif self.current_option == 'rupCheck':
            self.excluded_checks.difference_update(BLUE_RUPEES)
        else:
            locs = settings_manager.CHECK_LOCATIONS[self.current_option]
            if checked:
                self.excluded_checks.difference_update(locs)
            else:
                self.excluded_checks.update(locs)

        self.updateSettingsString()


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

        self.updateSettingsString()


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
        
        if value in [1, 3] and not self.ui.rapidsCheck.isChecked():
            self.excluded_checks.update(['owl-statue-rapids'])

        self.updateSettingsString()


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
        
        logic_defs = yaml.safe_load(self.logic_defs)
        
        seed = self.ui.lineEdit_3.text().strip()
        if seed.lower() in ('', 'random'):
            random.seed()
            seed = str(random.getrandbits(32))
        else:
            seed = seed[:32]
            valid_chars = string.ascii_letters + string.digits
            valid_chars = [c for c in valid_chars]
            for c in seed:
                if c not in valid_chars:
                    self.showUserError(f"Invalid seed character: {c}")
                    return
        
        # load mod settings from the UI, no need to decode settings string
        settings = settings_manager.loadRandomizerSettings(self, seed)
        settings_string = self.ui.lineEdit_4.text()
        outdir = f"{self.ui.lineEdit_2.text()}/{settings['seed']}"
        self.progress_window = ProgressWindow(rom_path, outdir, ITEM_DEFS, logic_defs, settings, settings_string)
        self.progress_window.setFixedSize(472, 125)
        self.progress_window.setWindowTitle(f"{settings['seed']}")

        if self.mode == 'light':
            self.progress_window.setStyleSheet(LIGHT_STYLESHEET)
        else:
            self.progress_window.setStyleSheet(DARK_STYLESHEET)
        
        self.progress_window.show()

    def getValidLocationChecks(self, locationList):
        return [loc for loc in locationList
                if (loc in DUNGEON_OWLS and self.dungeon_owls)
                or (loc in OVERWORLD_OWLS and self.overworld_owls)
                or (loc in BLUE_RUPEES and self.ui.rupCheck.isChecked())
                or (loc not in DUNGEON_OWLS and loc not in OVERWORLD_OWLS and loc not in BLUE_RUPEES)
                ]

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
            checks = self.getValidLocationChecks(TOTAL_CHECKS.difference(self.excluded_checks))
            for check in checks:
                self.ui.listWidget.addItem(SmartListWidget(self.checkToList(str(check))))
            
            self.ui.listWidget_2.clear()
            checks = self.getValidLocationChecks(self.excluded_checks)
            for check in checks:
                self.ui.listWidget_2.addItem(SmartListWidget(self.checkToList(str(check))))
            
            return
        
        # logic tricks
        if self.ui.tabWidget.currentIndex() == 3:
            return
    

    def includeButton_Clicked(self):
        for i in self.ui.listWidget_2.selectedItems():
            self.ui.listWidget_2.takeItem(self.ui.listWidget_2.row(i))
            self.excluded_checks.remove(self.listToCheck(i.text()))
            self.ui.listWidget.addItem(SmartListWidget(i.text()))
        self.updateSettingsString()


    def excludeButton_Clicked(self):
        for i in self.ui.listWidget.selectedItems():
            self.ui.listWidget.takeItem(self.ui.listWidget.row(i))
            self.ui.listWidget_2.addItem(SmartListWidget(i.text()))
            self.excluded_checks.add(self.listToCheck(i.text()))
        self.updateSettingsString()


    def includeButton_3_Clicked(self):
        for i in self.ui.listWidget_6.selectedItems():
            self.ui.listWidget_6.takeItem(self.ui.listWidget_6.row(i))
            self.starting_gear.remove(self.listToItem(i.text()))
            self.ui.listWidget_5.addItem(i.text())
        self.updateSettingsString()


    def excludeButton_3_Clicked(self):
        for i in self.ui.listWidget_5.selectedItems():
            self.ui.listWidget_5.takeItem(self.ui.listWidget_5.row(i))
            self.ui.listWidget_6.addItem(i.text())
            self.starting_gear.append(self.listToItem(i.text()))
        self.updateSettingsString()


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
        self.createMessageWindow("What's New", CHANGE_LOG)
    

    # Display new window to let the user know what went wrong - missing romfs/output path, bad custom logic, etc.
    def showUserError(self, msg):
        self.createMessageWindow("Error", msg)
    

    # Display new window listing the currently known issues
    def showIssues(self):
        self.createMessageWindow("Known Issues", KNOWN_ISSUES)
    

    def showTips(self):
        self.createMessageWindow("Helpful Tips", HELPFUL_TIPS)


    # Display new window with information about the randomizer
    def showInfo(self):
        self.createMessageWindow("Link's Awakening Switch Randomizer", ABOUT_INFO)
    

    def createMessageWindow(self, title, text):
        message = QtWidgets.QMessageBox()
        message.setWindowTitle(title)
        message.setText(text)

        if self.mode == 'light':
            message.setStyleSheet(LIGHT_STYLESHEET)
        else:
            message.setStyleSheet(DARK_STYLESHEET)
        
        message.exec()
    

    def pasteSettingsString(self):
        try:
            new_settings = settings_manager.decodeSettings(self.clipboard.text())
            if new_settings:
                settings_manager.loadSettings(self, new_settings)
                self.ui.lineEdit_4.setText(self.clipboard.text())
                self.tab_Changed()
        except: # Lots of potential different errors, so we use a general except to be safe
            self.showUserError('Could not decode settings string!')


    def randomizeSettings(self):
        new_settings = settings_manager.randomizeSettings(self)
        settings_manager.loadSettings(self, new_settings)
        self.tab_Changed()


    # Override mouse click event to make certain stuff lose focus
    def mousePressEvent(self, event):
        focused_widget = self.focusWidget()
        if isinstance(focused_widget, QtWidgets.QLineEdit) |\
            isinstance(focused_widget, QtWidgets.QComboBox) |\
            isinstance(focused_widget, QtWidgets.QSpinBox):
                focused_widget.clearFocus()
    

    # Override close event to save settings
    def closeEvent(self, event):
        settings_manager.saveSettings(self)
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
