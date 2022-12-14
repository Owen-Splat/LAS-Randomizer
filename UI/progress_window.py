from PySide6 import QtWidgets
from UI.ui_progress_form import Ui_ProgressWindow

from shuffler import ItemShuffler
from mod_generator import ModsProcess

import os
import copy
import shutil



class ProgressWindow(QtWidgets.QMainWindow):
    
    def __init__(self, rom_path, out_dir, seed, logic, item_defs, logic_defs, settings):
        super (ProgressWindow, self).__init__()
        self.ui = Ui_ProgressWindow()
        self.ui.setupUi(self)
        
        self.rom_path = rom_path
        self.out_dir = out_dir
        self.seed = seed
        self.logic = logic
        self.item_defs = copy.deepcopy(item_defs)
        self.logic_defs = copy.deepcopy(logic_defs)
        self.settings = settings
        
        self.valid_placements = 187 - len(self.settings['excluded-locations'])
        self.num_of_mod_files = 246
        
        if settings['shuffle-bombs']:
            self.num_of_mod_files -= 1
        
        if not settings['blup-sanity']:
            self.num_of_mod_files -= 1
        
        # if not settings['shuffle-companions']:
        #     self.num_of_mod_files -= 8
        
        if settings['randomize-music']:
            self.num_of_mod_files += 69
        
        if settings['randomize-enemies']:
            self.num_of_mod_files += 192
        
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
        self.ui.progressBar.setMaximum(self.valid_placements)
        self.ui.label.setText(f'Shuffling item placements...')
        self.shuffler_process =\
            ItemShuffler(self.rom_path, f'{self.out_dir}/01006BB00C6F0000',
                self.seed, self.logic, self.settings, self.item_defs, self.logic_defs)
        self.shuffler_process.setParent(self)
        self.shuffler_process.progress_update.connect(self.updateProgress)
        self.shuffler_process.give_placements.connect(self.receivePlacements)
        self.shuffler_process.is_done.connect(self.shufflerDone)
        self.shuffler_process.error.connect(self.shufflerError)
        self.shuffler_process.start() # start the item shuffler        


    # receives the int signal as a parameter named progress
    def updateProgress(self, progress):
        self.ui.progressBar.setValue(progress)
    
    
    # receive the placements from the shuffler thread to the modgenerator
    def receivePlacements(self, placements):
        self.placements = placements
    

    def shufflerError(self):
        self.shuffle_error = True


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
        self.ui.progressBar.setMaximum(self.num_of_mod_files)
        self.ui.label.setText(f'Generating mod files...')
        self.mods_process = ModsProcess(self.placements, self.rom_path, f'{self.out_dir}/01006BB00C6F0000', self.item_defs, self.seed)
        self.mods_process.setParent(self)
        self.mods_process.progress_update.connect(self.updateProgress)
        self.mods_process.is_done.connect(self.modsDone)
        self.mods_process.error.connect(self.modsError)
        self.mods_process.start() # start the modgenerator

    
    def modsError(self):
        self.mods_error = True


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
        
        self.ui.progressBar.setValue(self.num_of_mod_files)
        self.ui.label.setText("All done! Check the Github page for instructions on how to play!")
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
