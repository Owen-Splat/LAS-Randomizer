import platform
import subprocess
from pathlib import Path

from PySide6 import QtWidgets
from RandomizerUI.UI.ui_progress_form import Ui_ProgressWindow
from RandomizerCore.shuffler import ItemShuffler
from RandomizerCore.mod_generator import ModsProcess
import os
import copy
import shutil



class ProgressWindow(QtWidgets.QMainWindow):
    
    def __init__(self, rom_path, out_dir, item_defs, logic_defs, settings, settings_string):
        super (ProgressWindow, self).__init__()
        self.ui = Ui_ProgressWindow()
        self.ui.setupUi(self)

        self.rom_path : str = rom_path
        self.out_dir : str = out_dir
        self.seed : str = settings['seed']
        self.randstate = None
        self.logic : str = settings['logic']
        self.item_defs = copy.deepcopy(item_defs)
        self.logic_defs = copy.deepcopy(logic_defs)
        self.settings = copy.deepcopy(settings)
        self.settings_string : str = settings_string
        
        self.num_of_mod_tasks = 255

        self.ui.openOutputFolder.setVisible(False)
        self.ui.openOutputFolder.clicked.connect(self.openOutputFolderButtonClicked)

        # if not settings['shuffle-companions']:
        #     self.num_of_mod_files += 8

        if settings['blupsanity']:
            self.num_of_mod_tasks += 1
        
        if settings['owl-dungeon-gifts']:
            self.num_of_mod_tasks += 4 # 4 extra room modifications
        
        if settings['randomize-music']:
            self.num_of_mod_tasks += (102 + 13) # all .lvb files + extra events
        
        if settings['bad-pets']:
            self.num_of_mod_tasks += 10
        
        modded_enemies = 0
        if settings['randomize-enemies']:
            modded_enemies = 313
        if settings['randomize-enemy-sizes']:
            modded_enemies = 323
        self.num_of_mod_tasks += modded_enemies

        if settings['shuffle-dungeons']:
            self.num_of_mod_tasks += 19
        
        if settings['classic-d2']:
            self.num_of_mod_tasks += 1
        
        if settings['open-mabe']:
            self.num_of_mod_tasks += 4
        
        if settings['chest-aspect'] == 'camc':
            self.num_of_mod_tasks += 65 # len(PANEL_CHEST_ROOMS)
        
        self.done = False
        self.cancel = False

        self.shuffle_error = False
        self.mods_error = False

        self.shuffler_done = False
        self.mods_done = False
        
        self.placements = {}

        if os.path.exists(self.out_dir): # remove old mod files if generating a new one with the same seed
            shutil.rmtree(self.out_dir, ignore_errors=True)

        # initialize the shuffler thread
        self.current_job = 'shuffler'
        self.ui.progressBar.setMaximum(0) # busy status instead of direct progress
        self.ui.label.setText(f'Shuffling item placements...')
        self.shuffler_process =\
            ItemShuffler(self.out_dir, self.seed, self.logic, self.settings, self.item_defs, self.logic_defs)
        self.shuffler_process.setParent(self)
        self.shuffler_process.give_placements.connect(self.receivePlacements)
        self.shuffler_process.is_done.connect(self.shufflerDone)
        self.shuffler_process.error.connect(self.shufflerError)
        self.shuffler_process.start() # start the item shuffler
    

    # receives the int signal as a parameter named progress
    def updateProgress(self, progress):
        self.ui.progressBar.setValue(progress)
    

    # receive the placements from the shuffler thread to the modgenerator
    def receivePlacements(self, placements):
        self.placements = placements[0]
        self.randstate = placements[1]
    

    def shufflerError(self, er_message=str):
        self.shuffle_error = True
        from RandomizerCore.Paths.randomizer_paths import LOGS_PATH
        with open(LOGS_PATH, 'w') as f:
            f.write(f'{self.seed} - {self.logic.capitalize()} Logic')
            f.write(f'\n{self.settings_string}')
            f.write(f'\n\n{er_message}')
            f.write(f'\n\n{self.settings}')
    

    # receive signals when threads are done
    def shufflerDone(self):
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
        self.ui.progressBar.setValue(0)
        self.ui.progressBar.setMaximum(self.num_of_mod_tasks)
        self.ui.progressBar.setTextVisible(True)
        self.ui.progressBar.setFormat("%p%")
        self.ui.label.setText(f'Generating mod files...')
        self.mods_process = ModsProcess(self.placements, self.rom_path, f'{self.out_dir}', self.item_defs, self.seed, self.randstate)
        self.mods_process.setParent(self)
        self.mods_process.progress_update.connect(self.updateProgress)
        self.mods_process.is_done.connect(self.modsDone)
        self.mods_process.error.connect(self.modsError)
        self.mods_process.start() # start the modgenerator

    
    def modsError(self, er_message=str):
        self.mods_error = True
        from RandomizerCore.Paths.randomizer_paths import LOGS_PATH
        with open(LOGS_PATH, 'w') as f:
            f.write(f"{self.seed} - {self.logic.capitalize()} Logic")
            f.write(f'\n{self.settings_string}')
            f.write(f"\n\n{er_message}")
            f.write(f"\n\n{self.settings}")


    def modsDone(self):
        if self.mods_error:
            self.ui.label.setText("Error detected! Please check that your romfs are valid!")
            if os.path.exists(self.out_dir): # delete files if user canceled
                shutil.rmtree(self.out_dir, ignore_errors=True)
            self.done = True
            return
        
        if self.cancel:
            self.ui.label.setText("Canceling...")
            if os.path.exists(self.out_dir): # delete files if user canceled
                shutil.rmtree(self.out_dir, ignore_errors=True)
            self.done = True
            self.close()
            return
        
        self.ui.progressBar.setValue(self.num_of_mod_tasks)
        self.ui.label.setText("All done! Check the README for instructions on how to play!")
        self.ui.progressBar.setVisible(False)
        self.ui.openOutputFolder.setVisible(True)
        self.done = True


    # override the window close event to close the randomization thread
    def closeEvent(self, event):
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

    def openFolder(self, path):
        if platform.system() == "Windows":
            os.startfile(path)
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])

    def openOutputFolderButtonClicked(self):
        self.openFolder(Path(self.out_dir).parent.absolute())
        self.window().close()