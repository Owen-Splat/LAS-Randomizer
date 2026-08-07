from PySide6.QtGui import QScreen
from PySide6.QtWidgets import (QFileDialog, QMainWindow, QWidget,
                               QCheckBox, QComboBox, QLineEdit, QSpinBox,
                               QMessageBox, QApplication)
from RandomizerUI.UI.custom_widgets import *
from RandomizerUI.UI.ui_main import Ui_MainWindow
from RandomizerUI.progress_window import ProgressWindow
from RandomizerUI.update import UpdateProcess, LogicUpdateProcess
from RandomizerCore.randomizer_data import *
from pathlib import Path
import random, re, string
from RandomizerUI.settings_manager import SettingsManager, CHECK_LOCATIONS


class MainWindow(QMainWindow):
    def __init__(self):
        super(MainWindow, self).__init__()
        self.clipboard = QApplication.clipboard()
        self.excluded_checks = set()
        self.starting_gear = list()

        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.ui.setupSignals()

        # Load User Settings
        self.settings = SettingsManager(self.ui)
        self.applyDefaults()
        if not DEFAULTS:
            self.settings.load()

        self.updateOwls()
        self.updateSeashells()
        self.updateStartingHeartsText()
        self.toggleRaceMode()

        # Check for app & logic updates
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

        # move to center
        center = QScreen.availableGeometry(QApplication.primaryScreen()).center()
        geo = self.frameGeometry()
        geo.moveCenter(center)
        self.move(geo.topLeft())


    def applyDefaults(self):
        self.settings.reset()


    def updateSettingsString(self):
        self.ui.findLineEdit("SettingsLine").setText(self.settings.encode())


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
        """Called when the seed button is clicked"""

        adj1 = random.choice(ADJECTIVES)
        adj2 = random.choice(ADJECTIVES)
        char = random.choice(CHARACTERS)
        line = self.ui.findLineEdit('SeedLine')
        line.setText(adj1 + adj2 + char)


    def checkClicked(self, checkbox: QCheckBox):
        """Called every time a QCheckBox is clicked"""

        match checkbox.text():
            case "Rapids":
                if checkbox.isChecked():
                    self.excluded_checks.difference_update(RAPIDS_REWARDS)
                    self.excluded_checks.difference_update(['owl-statue-rapids'])
                else:
                    self.excluded_checks.update(RAPIDS_REWARDS)
                    if self.overworld_owls:
                        self.excluded_checks.update(['owl-statue-rapids'])
            case "Blue Rupees":
                self.excluded_checks.difference_update(BLUE_RUPEES)
            case _:
                pass
                if checkbox.text() in CHECK_LOCATIONS:
                    locs = CHECK_LOCATIONS[checkbox.text()]
                    if checkbox.isChecked():
                        self.excluded_checks.difference_update(locs)
                    else:
                        self.excluded_checks.update(locs)


    def updateSeashells(self):
        match self.ui.findComboBox("Seashell Mansion:  ").currentIndex():
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


    def updateOwls(self):
        match self.ui.findComboBox("Owl Gifts:  ").currentIndex():
            case 0:
                self.overworld_owls = False
                self.excluded_checks.difference_update(OVERWORLD_OWLS)
                self.dungeon_owls = False
                self.excluded_checks.difference_update(DUNGEON_OWLS)
            case 1:
                self.overworld_owls = True
                self.dungeon_owls = False
                self.excluded_checks.difference_update(DUNGEON_OWLS)
                if not self.ui.findCheckBox("Rapids").isChecked():
                    self.excluded_checks.update(['owl-statue-rapids'])
            case 2:
                self.overworld_owls = False
                self.excluded_checks.difference_update(OVERWORLD_OWLS)
                self.dungeon_owls = True
            case 3:
                self.overworld_owls = True
                self.dungeon_owls = True
                if not self.ui.findCheckBox("Rapids").isChecked():
                    self.excluded_checks.update(['owl-statue-rapids'])


    def updateStartingHeartsText(self) -> None:
        num_pieces = self.ui.findSpinBox("Pieces:  ").value()
        num_containers = self.ui.findSpinBox("Containers:  ").value()
        total_hearts = 3 + num_containers + int(num_pieces // 4)
        label = self.ui.findLabel("StartingHeartsText")
        label.setText(f"Starting hearts:  {total_hearts}")


    def toggleRaceMode(self) -> None:
        toggled = self.ui.findCheckBox("Race Mode").isChecked()
        self.ui.findComboBox("Required Dungeons:  ").setDisabled(not toggled)
        self.ui.findCheckBox("Create Spoiler Log").setEnabled(not toggled)


    # Randomize Button Clicked
    def randomizeButton_Clicked(self):
        # verify RomFS before shuffling items
        rom_path = self.ui.findLineEdit("RomfsLine").text()

        if not Path(rom_path).exists() and rom_path != "":
            self.ui.showUserError('Romfs path does not exist!')
            return

        if (Path(rom_path) / 'romfs').exists():
            rom_path = Path(rom_path) / 'romfs'
            self.ui.findLineEdit("RomfsLine").setText(str(rom_path))

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
        settings = self.settings.fetch()
        logic = settings["Settings"]["Preset"]
        if logic != "No Logic":
            logic += " Logic"
        settings["Settings"]["Seashells Important"] = True if len([s for s in SEASHELL_REWARDS if s not in self.excluded_checks]) > 0 else False
        settings["Settings"]["Trade Important"] = True if len([t for t in TRADE_GIFT_LOCATIONS if t not in self.excluded_checks]) > 0 else False
        settings_string = self.ui.findLineEdit("SettingsLine").text()
        self.progress_window = ProgressWindow(ITEM_DEFS, LOGIC_DEFS, settings, settings_string)
        self.progress_window.setWindowTitle(f"{seed} - {logic}")

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
                or (loc in BLUE_RUPEES and self.ui.findCheckBox("Blue Rupees").isChecked())
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
                random_list.sortItems()

                start_list = self.ui.findListWidget("StartingItemsList")
                start_list.clear()
                for item in self.starting_gear:
                    start_list.addItem(self.checkToList(str(item)))
                start_list.sortItems()

            case "Locations":
                include_list = self.ui.findListWidget("IncludedLocationsList")
                include_list.clear()
                checks = self.getValidLocationChecks(TOTAL_CHECKS.difference(self.excluded_checks))
                for check in checks:
                    include_list.addItem(RandoListItem(self.checkToList(str(check))))
                include_list.sortItems()

                exclude_list = self.ui.findListWidget("ExcludedLocationsList")
                exclude_list.clear()
                checks = self.getValidLocationChecks(self.excluded_checks)
                for check in checks:
                    exclude_list.addItem(RandoListItem(self.checkToList(str(check))))
                exclude_list.sortItems()

            case "Logic":
                pass


    def moveListItemsRight(self) -> None:
        tab_name = self.ui.getCurrentTabName()
        match tab_name:
            case "Starting Items":
                left_list = self.ui.findListWidget("RandomItemsList")
                right_list = self.ui.findListWidget("StartingItemsList")
                for i in left_list.selectedItems():
                    left_list.takeItem(left_list.row(i))
                    right_list.addItem(i.text())
                    self.starting_gear.append(self.listToItem(i.text()))
                right_list.sortItems()

            case "Locations":
                left_list = self.ui.findListWidget("IncludedLocationsList")
                right_list = self.ui.findListWidget("ExcludedLocationsList")
                for i in left_list.selectedItems():
                    left_list.takeItem(left_list.row(i))
                    right_list.addItem(RandoListItem(i.text()))
                    self.excluded_checks.add(self.listToCheck(i.text()))
                right_list.sortItems()

            case "Logic":
                pass

        self.updateSettingsString()


    def moveListItemsLeft(self) -> None:
        tab_name = self.ui.getCurrentTabName()
        match tab_name:
            case "Starting Items":
                left_list = self.ui.findListWidget("RandomItemsList")
                right_list = self.ui.findListWidget("StartingItemsList")
                for i in right_list.selectedItems():
                    right_list.takeItem(right_list.row(i))
                    left_list.addItem(i.text())
                    self.starting_gear.remove(self.listToItem(i.text()))
                left_list.sortItems()

            case "Locations":
                left_list = self.ui.findListWidget("IncludedLocationsList")
                right_list = self.ui.findListWidget("ExcludedLocationsList")
                for i in right_list.selectedItems():
                    right_list.takeItem(right_list.row(i))
                    left_list.addItem(RandoListItem(i.text()))
                    self.excluded_checks.remove(self.listToCheck(i.text()))
                left_list.sortItems()

            case "Logic":
                pass

        self.updateSettingsString()


    # some-check to Some Check
    def checkToList(self, check):
        s = re.sub("-", " ", check).title()
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
            new_settings = self.settings.decode(self.clipboard.text())
            if new_settings:
                self.settings.load(self, new_settings)
                self.ui.findLineEdit("SettingsLine").setText(self.clipboard.text())
                self.tabChanged()
        except: # Lots of potential different errors, so we use a general except to be safe
            self.ui.showUserError('Could not decode settings string!')


    def randomizeSettings(self):
        self.settings.randomize()
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
        self.settings.save()
        event.accept()
