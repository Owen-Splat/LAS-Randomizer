import platform
import subprocess
from pathlib import Path

from PySide6 import QtWidgets
from RandomizerUI.UI.ui_progress import Ui_ProgressWindow
from RandomizerCore.shuffler import ItemShuffler
from RandomizerCore.mod_generator import ModsProcess
import copy, shutil, os


class ProgressWindow(QtWidgets.QMainWindow):
    """A window for showing the progress of the seed generation"""

    def __init__(self, item_defs: dict, logic_defs: dict, settings: dict, settings_string: str) -> None:
        super (ProgressWindow, self).__init__()
        self.ui = Ui_ProgressWindow()
        self.ui.setupUi(self)

        self.randstate = None
        self.seed : str = settings["Seed"]

        # outdir should contain the seed name for console
        # but if the path points to an emulator, the outdir should be the title id folder
        out_dir: Path = settings["Output"]
        if any(s for s in ("sdcard", "sdmc") if s in str(out_dir).lower()):
            self.del_dir = out_dir / "atmosphere" / "contents" / "01006BB00C6F0000"
            self.out_dir = out_dir
        else:
            self.del_dir = out_dir / self.seed
            self.out_dir = out_dir / self.seed

        # store the parent folder of the atmosphere folder to delete

        self.item_defs: dict = copy.deepcopy(item_defs)
        self.logic_defs: dict = copy.deepcopy(logic_defs)
        for k,v in settings["Settings"].items():
            settings[k] = v
        del settings["Settings"]
        self.settings: dict = settings
        self.settings_string : str = settings_string

        self.num_of_mod_tasks = 369 #255

        # if not settings['shuffle-companions']:
        #     self.num_of_mod_files += 8

        if settings["Blue Rupees"]:
            self.num_of_mod_tasks += 2

        if settings["Owl Gifts"] == "Overworld":
            self.num_of_mod_tasks += 1
        elif settings["Owl Gifts"] == "Dungeons":
            self.num_of_mod_tasks += 5
        elif settings["Owl Gifts"] == "All":
            self.num_of_mod_tasks += 6

        if settings["Music"] != "Vanilla":
            self.num_of_mod_tasks += 124

        if settings["Bad Pets"]:
            self.num_of_mod_tasks += 9

        if settings["Shuffled Dungeons"]:
            self.num_of_mod_tasks += 19

        if settings["Classic D2"]:
            self.num_of_mod_tasks += 1

        if settings["Open Mabe"]:
            self.num_of_mod_tasks += 4

        if settings["Randomize Enemies"]:
            self.num_of_mod_tasks += 2

        if settings["Chest Types"] == "Texture + Size":
            self.num_of_mod_tasks += 65

        if settings["Randomize Environments"]:
            self.num_of_mod_tasks += 102

        if settings["Randomize Text"]:
            self.num_of_mod_tasks += 34

        self.done = False
        self.cancel = False

        self.shuffle_error = False
        self.mods_error = False

        self.shuffler_done = False
        self.mods_done = False

        self.placements = {}

        if self.del_dir.exists(): # remove old mod files
            shutil.rmtree(self.del_dir, ignore_errors=True)

        # initialize the shuffler thread
        self.current_job = 'shuffler'
        self.ui.label.setText(f'Shuffling item placements...')
        self.shuffler_process =\
            ItemShuffler(self.settings, self.item_defs, self.logic_defs)
        self.shuffler_process.setParent(self)
        self.shuffler_process.give_placements.connect(self.receivePlacements)
        self.shuffler_process.is_done.connect(self.shufflerDone)
        self.shuffler_process.error.connect(self.shufflerError)
        self.shuffler_process.start() # start the item shuffler


    def updateProgress(self, progress: int) -> None:
        """Receives the current number of complete tasks to display with the progress bar"""
        self.ui.progress_bar.setValue(progress)


    def receivePlacements(self, placements) -> None:
        """Receives the placements and current random state from the shuffler thread"""
        self.placements = placements[0]
        self.randstate = placements[1]


    def shufflerError(self, er_message=str) -> None:
        """Called when the shuffler thread encounters an error and writes the error to a file"""
        self.shuffle_error = True
        from RandomizerCore.Paths.randomizer_paths import LOGS_PATH
        with open(LOGS_PATH, 'w') as f:
            f.write(f'{self.seed} - {self.logic.capitalize()} Logic')
            f.write(f'\n{self.settings_string}')
            f.write(f'\n\n{er_message}')
            f.write(f'\n\n{self.settings}')


    def shufflerDone(self) -> None:
        """Receives a signal when the shuffler is done. If no error, start the modgenerator thread"""
        if self.shuffle_error:
            self.ui.label.setText("Something went wrong! Please report this to either GitHub or Discord!")
            self.done = True
            return

        if self.cancel:
            self.done = True
            self.close()
            return

        # initialize the modgenerator thread
        self.current_job = 'modgenerator'
        self.ui.progress_bar.setValue(0)
        self.ui.progress_bar.setMaximum(self.num_of_mod_tasks)
        self.ui.progress_bar.setTextVisible(True)
        self.ui.progress_bar.setFormat("%p%")
        self.ui.label.setText(f'Generating mod files...')
        self.mods_process = ModsProcess(self.placements, self.settings["RomFS"], self.out_dir, self.item_defs, self.seed, self.randstate)
        self.mods_process.setParent(self)
        self.mods_process.progress_update.connect(self.updateProgress)
        self.mods_process.is_done.connect(self.modsDone)
        self.mods_process.error.connect(self.modsError)
        self.mods_process.start() # start the modgenerator


    def modsError(self, er_message=str) -> None:
        """Receives a signal when the modgenerator is done. If no error, start the modgenerator thread"""
        self.mods_error = True
        from RandomizerCore.Paths.randomizer_paths import LOGS_PATH
        with open(LOGS_PATH, 'w') as f:
            f.write(f"{self.seed} - {self.settings["Preset"]} Logic")
            f.write(f'\n{self.settings_string}')
            f.write(f"\n\n{er_message}")
            f.write(f"\n\n{self.settings}")


    def modsDone(self) -> None:
        """Receives a signal when the modgenerator is done. If no error, display the finish text and button"""
        if self.mods_error:
            self.ui.label.setText("Error detected! Please check that your romfs are valid!")
            if self.del_dir.exists(): # delete files if user canceled
                shutil.rmtree(self.del_dir, ignore_errors=True)
            self.done = True
            return

        if self.cancel:
            self.ui.label.setText("Canceling...")
            if self.del_dir.exists(): # delete files if user canceled
                shutil.rmtree(self.del_dir, ignore_errors=True)
            self.done = True
            self.close()
            return

        self.ui.progress_bar.setValue(self.num_of_mod_tasks)
        self.ui.label.setText("All done! Check the README for instructions on how to play!")
        self.ui.progress_bar.setVisible(False)
        self.ui.folder_button.setVisible(True)
        self.done = True


    def closeEvent(self, event) -> None:
        """Overrides the window close event to stop any running threads"""
        if self.done:
            event.accept()
        else:
            event.ignore()
            self.cancel = True
            self.ui.label.setText('Canceling...')
            if self.current_job == 'shuffler':
                self.shuffler_process.stop()
            elif self.current_job == 'modgenerator':
                self.mods_process.stop()


    def openFolder(self, path) -> None:
        """Opens the output folder"""
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])


    def openOutputFolderButtonClicked(self) -> None:
        """Opens the output folder when the user clicks on the button"""
        out_path = self.out_dir
        if out_path.name != self.seed:
            out_path = self.out_dir / "atmosphere" / "contents" / "01006BB00C6F0000"
        self.openFolder(out_path)
        self.window().close()
