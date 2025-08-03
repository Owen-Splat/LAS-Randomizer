from PySide6.QtCore import QEvent
from PySide6.QtGui import QClipboard
from PySide6.QtWidgets import (QFileDialog, QMainWindow, QWidget,
                               QCheckBox, QComboBox, QLineEdit, QSpinBox,
                               QMessageBox)
from RandomizerUI.UI.custom_widgets import *
from RandomizerUI.UI.ui_main import Ui_MainWindow
from RandomizerUI.progress_window import ProgressWindow
from RandomizerUI.update import UpdateProcess, LogicUpdateProcess
from RandomizerCore.randomizer_data import *
from pathlib import Path
import random, re, string
import RandomizerUI.settings_manager as settings_manager


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.addOptionDescriptions()

        # Keep track of stuff
        self.excluded_checks = set()
        self.starting_gear = list()
        self.overworld_owls = bool(False)
        self.dungeon_owls = bool(False)
        self.current_option = ''
        self.clipboard = QClipboard()

        # Load User Settings
        self.applyDefaults()
        if not DEFAULTS:
            settings_manager.loadSettings(self)

        self.updateOwls()
        self.updateSeashells()

        ### SUBSCRIBE TO EVENTS
        self.ui.findLineEdit("SeedLine").textChanged.connect(self.updateSettingsString)
        self.ui.findPushButton("CopyButton").clicked.connect(lambda x: self.clipboard.setText(self.ui.findLineEdit("SettingsLineEdit").text()))
        self.ui.findPushButton("PasteButton").clicked.connect(self.pasteSettingsString)
        self.ui.findPushButton("ResetButton").clicked.connect(self.applyDefaults)
        self.ui.findPushButton("RandomSettingsButton").clicked.connect(self.randomizeSettings)
        self.ui.findPushButton("RandomizeButton").clicked.connect(self.randomizeButton_Clicked)
        self.ui.findComboBox("MansionBox").currentIndexChanged.connect(self.updateSeashells)
        self.ui.findComboBox("OwlsBox").currentIndexChanged.connect(self.updateOwls)
        self.ui.findComboBox("TrapBox").currentIndexChanged.connect(self.updateSettingsString)
        self.ui.findComboBox("InstrumentStartBox").currentIndexChanged.connect(self.updateSettingsString)
        self.ui.findComboBox("LogicBox").currentIndexChanged.connect(self.updateSettingsString)
        self.ui.findComboBox("StealingBox").currentIndexChanged.connect(self.updateSettingsString)
        self.ui.findComboBox("ChestTypeBox").currentIndexChanged.connect(self.updateSettingsString)
        self.ui.findSpinBox("RupeeBox").valueChanged.connect(self.updateSettingsString)
        # self.ui.tabWidget.currentChanged.connect(self.tab_Changed)

        # center = QtGui.QScreen.availableGeometry(QtWidgets.QApplication.primaryScreen()).center()
        # geo = self.frameGeometry()
        # geo.moveCenter(center)
        # self.move(geo.topLeft())

        self.process = UpdateProcess()
        self.process.can_update.connect(self.showUpdate)
        self.process.give_version.connect(self.obtainVersion)
        self.process.start()

        match self.ui.theme:
            case 'dark':
                self.ui.setDarkMode()
            case 'diamond-black':
                self.ui.setDiamondBlackMode()
            case _:
                self.ui.setLightMode()

        self.show()


    def applyDefaults(self):
        settings_manager.applyDefaults(self)


    def updateSettingsString(self):
        self.ui.findLineEdit("SettingsLineEdit").setText(settings_manager.encodeSettings(self))


    def obtainVersion(self, version):
        self.new_version = version


    def showUpdate(self, update):
        if not update:
            return

        update_menu = self.menuBar().addMenu('NEW VERSION AVAILABLE!')
        update_action = update_menu.addAction('Update')
        update_action.triggered.connect(self.updateClicked)
        self.updateClicked() # Show the update window anyway, the menu button exists in case the user does not want to immediately update


    def updateClicked(self):
        self.ui.createMessageWindow(
            "Link's Awakening Switch Randomizer Update",
            f"""
            Current version: {APP_VERSION}<br></br>
            <br></br>

            New version: {self.new_version}<br></br>
            <br></br>

            <a href="{DOWNLOAD_PAGE}" style="color: rgb(31, 81, 255);">{DOWNLOAD_PAGE}</a>"""
        )


    def browseButton_Clicked(self, line_name: str) -> None:
        """Opens a QFileDialog when a browse button is clicked and sets the text of the corresponding QLineEdit"""

        line = self.ui.findLineEdit(line_name)
        dir = line.text()
        if not Path(dir).exists():
            dir = ''
        folder = self.ui.openFileBrowser(dir)
        if folder != '' and Path(folder).exists():
            line.setText(str(Path(folder)))


    def generateSeed(self):
        adj1 = random.choice(ADJECTIVES)
        adj2 = random.choice(ADJECTIVES)
        char = random.choice(CHARACTERS)
        line = self.ui.findLineEdit('SeedLine')
        line.setText(adj1 + adj2 + char)


    def checkClicked(self, checked):
        if self.current_option not in settings_manager.CHECK_LOCATIONS:
            return

        match self.current_option:
            case "RapidsCheck":
                if checked:
                    self.excluded_checks.difference_update(RAPIDS_REWARDS)
                    self.excluded_checks.difference_update(['owl-statue-rapids'])
                else:
                    self.excluded_checks.update(RAPIDS_REWARDS)
                    if self.overworld_owls:
                        self.excluded_checks.update(['owl-statue-rapids'])
            case "RupeesCheck":
                self.excluded_checks.difference_update(BLUE_RUPEES)
            case _:
                locs = settings_manager.CHECK_LOCATIONS[self.current_option]
                if checked:
                    self.excluded_checks.difference_update(locs)
                else:
                    self.excluded_checks.update(locs)

        self.updateSettingsString()


    def updateSeashells(self):
        match self.ui.findComboBox("MansionBox").currentIndex():
            case 0:
                self.excluded_checks.update(SEASHELL_REWARDS)
            case 1:
                self.excluded_checks.difference_update(SEASHELL_REWARDS)
                self.excluded_checks.update(['15-seashell-reward', '30-seashell-reward', '40-seashell-reward', '50-seashell-reward'])
            case 2:
                self.excluded_checks.difference_update(SEASHELL_REWARDS)
                self.excluded_checks.update(['30-seashell-reward', '40-seashell-reward', '50-seashell-reward'])
            case 3:
                self.excluded_checks.difference_update(SEASHELL_REWARDS)
                self.excluded_checks.update(['40-seashell-reward', '50-seashell-reward'])
            case 4:
                self.excluded_checks.difference_update(SEASHELL_REWARDS)
                self.excluded_checks.update(['50-seashell-reward'])
            case _:
                self.excluded_checks.difference_update(SEASHELL_REWARDS)

        self.updateSettingsString()


    def updateOwls(self):
        match self.ui.findComboBox("OwlsBox").currentIndex():
            case 0:
                self.overworld_owls = False
                self.excluded_checks.difference_update(OVERWORLD_OWLS)
                self.dungeon_owls = False
                self.excluded_checks.difference_update(DUNGEON_OWLS)
            case 1:
                self.overworld_owls = True
                self.dungeon_owls = False
                self.excluded_checks.difference_update(DUNGEON_OWLS)
                if not self.ui.findCheckBox("RapidsCheck").isChecked():
                    self.excluded_checks.update(['owl-statue-rapids'])
            case 2:
                self.overworld_owls = False
                self.excluded_checks.difference_update(OVERWORLD_OWLS)
                self.dungeon_owls = True
            case 3:
                self.overworld_owls = True
                self.dungeon_owls = True
                if not self.ui.findCheckBox("RapidsCheck").isChecked():
                    self.excluded_checks.update(['owl-statue-rapids'])

        self.updateSettingsString()


    # Randomize Button Clicked
    def randomizeButton_Clicked(self):
        # verify RomFS before shuffling items
        rom_path = self.ui.findLineEdit("RomfsLine").text()

        if not Path(rom_path).exists() and rom_path != "":
            self.ui.showUserError('Romfs path does not exist!')
            return

        if (Path(rom_path) / 'romfs').exists():
            rom_path = Path(rom_path) / 'romfs'

        if not (Path(rom_path) / 'region_common' / 'event' / 'PlayerStart.bfevfl').is_file():
            self.ui.showUserError('RomFS path is not valid!')
            return

        out_path = self.ui.findLineEdit("OutputLine").text()
        if not Path(out_path).exists() and out_path != "":
            self.ui.showUserError('Output path does not exist!')
            return

        seed = self.ui.findLineEdit("SeedLine").text().strip()
        if seed.lower() in ('', 'random'):
            random.seed()
            seed = str(random.getrandbits(32))
        else:
            seed = seed[:32]
            valid_chars = string.ascii_letters + string.digits
            valid_chars = [c for c in valid_chars]
            for c in seed:
                if c not in valid_chars:
                    self.ui.showUserError(f"Invalid seed character: {c}")
                    return

        # load mod settings from the UI, no need to decode settings string
        settings = settings_manager.loadRandomizerSettings(self, seed)
        settings_string = self.ui.findLineEdit("SettingsLineEdit").text()
        outdir = f"{self.ui.findLineEdit('OutputLine').text()}/{settings['seed']}"
        self.progress_window = ProgressWindow(rom_path, outdir, ITEM_DEFS, LOGIC_DEFS, settings, settings_string)
        # self.progress_window.setWindowTitle(f"{settings['seed']}")

        match self.ui.theme:
            case "dark":
                self.progress_window.setStyleSheet(DARK_STYLESHEET)
            case "diamond-black":
                self.progress_window.setStyleSheet(DIAMONDBLACK_STYLESHEET)
            case _:
                self.progress_window.setStyleSheet(LIGHT_STYLESHEET)

        self.progress_window.show()


    def getValidLocationChecks(self, locationList):
        return [loc for loc in locationList
                if (loc in DUNGEON_OWLS and self.dungeon_owls)
                or (loc in OVERWORLD_OWLS and self.overworld_owls)
                or (loc in BLUE_RUPEES and self.ui.findCheckBox("RupeesCheck").isChecked())
                or (loc not in DUNGEON_OWLS and loc not in OVERWORLD_OWLS and loc not in BLUE_RUPEES)
                ]


    def tabChanged(self):
        match self.ui.getCurrentTabName():
            case "Starting Items":
                randomized_gear = STARTING_ITEMS[:]
                for x in self.starting_gear:
                    randomized_gear.remove(x)
                random_list = self.ui.findListWidget("RandomItemsList")
                random_list.clear()
                for item in randomized_gear:
                    random_list.addItem(self.checkToList(str(item)))
                start_list = self.ui.findListWidget("StartingItemsList")
                start_list.clear()
                for item in self.starting_gear:
                    start_list.addItem(self.checkToList(str(item)))

            case "Locations":
                include_list = self.ui.findListWidget("IncludedLocationsList")
                include_list.clear()
                checks = self.getValidLocationChecks(TOTAL_CHECKS.difference(self.excluded_checks))
                for check in checks:
                    include_list.addItem(RandoListWidget(self.checkToList(str(check))))
                exclude_list = self.ui.findListWidget("ExcludedLocationsList")
                exclude_list.clear()
                checks = self.getValidLocationChecks(self.excluded_checks)
                for check in checks:
                    exclude_list.addItem(RandoListWidget(self.checkToList(str(check))))

            case "Logic":
                pass


    # def includeButton_Clicked(self):
    #     for i in self.ui.listWidget_2.selectedItems():
    #         self.ui.listWidget_2.takeItem(self.ui.listWidget_2.row(i))
    #         self.excluded_checks.remove(self.listToCheck(i.text()))
    #         self.ui.listWidget.addItem(RandoListWidget(i.text()))
    #     self.updateSettingsString()


    # def excludeButton_Clicked(self):
    #     for i in self.ui.listWidget.selectedItems():
    #         self.ui.listWidget.takeItem(self.ui.listWidget.row(i))
    #         self.ui.listWidget_2.addItem(RandoListWidget(i.text()))
    #         self.excluded_checks.add(self.listToCheck(i.text()))
    #     self.updateSettingsString()


    # def includeButton_3_Clicked(self):
    #     for i in self.ui.listWidget_6.selectedItems():
    #         self.ui.listWidget_6.takeItem(self.ui.listWidget_6.row(i))
    #         self.starting_gear.remove(self.listToItem(i.text()))
    #         self.ui.listWidget_5.addItem(i.text())
    #     self.updateSettingsString()


    # def excludeButton_3_Clicked(self):
    #     for i in self.ui.listWidget_5.selectedItems():
    #         self.ui.listWidget_5.takeItem(self.ui.listWidget_5.row(i))
    #         self.ui.listWidget_6.addItem(i.text())
    #         self.starting_gear.append(self.listToItem(i.text()))
    #     self.updateSettingsString()


    def moveListItemsRight(self) -> None:
        tab_name = self.ui.getCurrentTabName()
        match tab_name:
            case "Starting Items": # set items to start with
                pass
            case "Locations": # set locations to exclude
                pass
            case "Logic": # set logic tricks to exclude
                pass


    def moveListItemsLeft(self) -> None:
        tab_name = self.ui.getCurrentTabName()
        match tab_name:
            case "Starting Items": # unset items to start with
                pass
            case "Locations": # set locations to include
                pass
            case "Logic": # set logic tricks to include
                pass


    # some-check to Some Check
    def checkToList(self, check):
        # slots = ('1St', '2Nd', '3Rd', '4Th', '5Th', '6Th', '7Th')

        s = re.sub("-", " ", check).title()

        # for slot in slots:
        #     s = s.replace(slot, slot.lower())

        return s


    # Some Check to some-check
    def listToCheck(self, check):
        stayUpper = ('d0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8')

        s = re.sub(" ", "-", check).lower()

        if s.startswith(stayUpper):
            s = s.replace('d', 'D', 1)

        return s


    # Starting Item to starting-item and also converts names that were changed to look nicer
    def listToItem(self, item):
        s = re.sub(" ", "-", item).lower()
        
        return s


    def pasteSettingsString(self):
        try:
            new_settings = settings_manager.decodeSettings(self.clipboard.text())
            if new_settings:
                settings_manager.loadSettings(self, new_settings)
                self.ui.lineEdit_4.setText(self.clipboard.text())
                self.tabChanged()
        except: # Lots of potential different errors, so we use a general except to be safe
            self.ui.showUserError('Could not decode settings string!')


    def randomizeSettings(self):
        new_settings = settings_manager.randomizeSettings(self)
        settings_manager.loadSettings(self, new_settings)
        self.tabChanged()


    # Override mouse click event to make certain stuff lose focus
    def mousePressEvent(self, event):
        focused_widget = self.focusWidget()
        if isinstance(focused_widget, QLineEdit) |\
            isinstance(focused_widget, QComboBox) |\
            isinstance(focused_widget, QSpinBox):
                focused_widget.clearFocus()


    # Override close event to save settings
    def closeEvent(self, event):
        settings_manager.saveSettings(self)
        event.accept()
