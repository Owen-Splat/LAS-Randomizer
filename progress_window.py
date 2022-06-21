from PySide6 import QtWidgets
from UI.progressForm import Ui_ProgressWindow

from shuffler import ItemShuffler
from mod_generator import ModsProcess

from randomizer_paths import DATA_PATH

import os
import shutil

import yaml


with open(os.path.join(DATA_PATH, 'Npc.yml'), 'r') as f:
    NEW_NPCS = yaml.safe_load(f)



class ProgressWindow(QtWidgets.QMainWindow):
    
    def __init__(self, rom_path, out_dir, seed, item_defs, logic_defs, settings):
        super (ProgressWindow, self).__init__()
        self.ui = Ui_ProgressWindow()
        self.ui.setupUi(self)
        
        self.rom_path = rom_path
        self.out_dir = out_dir
        self.seed = seed
        self.logic = 'None'
        self.item_defs = item_defs
        self.logic_defs = logic_defs
        self.settings = settings
        
        self.valid_placements = 228  # 226
        self.num_of_mod_files = 304 # +1 since it takes half a second after completing before it is actually done

        if settings['shuffle-bombs']:
            self.num_of_mod_files -= 1
        
        if not settings['shuffle-instruments']:
            self.valid_placements -= 8
            self.num_of_mod_files -= 8
        
        if not settings['randomize-music']:
            self.num_of_mod_files -= 69
        
        self.done = False
        self.cancel = False
        self.error =False

        self.shuffler_done = False
        self.mods_done = False
        
        self.placements = {}

        if os.path.exists(self.out_dir): # remove old mod files if generating a new one with the same seed
            shutil.rmtree(self.out_dir, ignore_errors=True)

        # start shuffler
        self.current_job = 'shuffler'
        self.ui.progressBar.setMaximum(self.valid_placements)
        self.ui.label.setText(f'Shuffling item placements...')
        # self.ui.label_2.setText(f'0/{self.valid_placements}')
        self.shuffler_process = ItemShuffler(self.rom_path, self.out_dir, self.seed, self.logic, self.settings, self.item_defs, self.logic_defs)
        self.shuffler_process.setParent(self)
        self.shuffler_process.progress_update.connect(self.UpdateProgress)
        self.shuffler_process.give_placements.connect(self.ReceivePlacements)
        self.shuffler_process.is_done.connect(self.AreItemsShuffled)
        self.shuffler_process.start() # start the item shuffler        


    # receives the int signal as a parameter named progress
    def UpdateProgress(self, progress):
        # if self.current_job == 'shuffler':
        #     self.ui.label_2.setText(f'{progress}/{self.valid_placements}')
        # elif self.current_job == 'modgenerator':
        #     self.ui.label_2.setText(f'{progress}/{self.num_of_mod_files}')
        self.ui.progressBar.setValue(progress)
    
    
    # receive the placements from the shuffler thread to the modgenerator
    def ReceivePlacements(self, placements):
        self.placements = placements
                

    # receive signals when threads are done
    def AreItemsShuffled(self, done):
        if done and not self.cancel: # make mod files
            self.current_job = 'modgenerator'
            self.ui.progressBar.setValue(0)
            self.ui.progressBar.setMaximum(self.num_of_mod_files)
            self.ui.label.setText(f'Generating mod files...')
            # self.ui.label_2.setText(f'0/{self.num_of_mod_files}')
            self.mods_process = ModsProcess(self.placements, self.rom_path, self.out_dir, self.item_defs, NEW_NPCS, self.seed)
            self.mods_process.setParent(self)
            self.mods_process.progress_update.connect(self.UpdateProgress)
            self.mods_process.is_done.connect(self.AreModsDone)
            self.mods_process.error.connect(self.modsError)
            self.mods_process.start()
        else:
            self.done = True
            self.close()


    
    def modsError(self, error):
        if error:
            self.error = True
            print('Error detected')



    def AreModsDone(self, done):
        if done:
            # All done
            if not self.cancel and not self.error:
                self.ui.progressBar.setValue(self.num_of_mod_files)
                self.ui.label.setText("All done! Check the Github page for instructions on how to play!")
                # self.ui.label_2.setText('')
                self.done = True
            elif self.error:
                self.ui.label.setText("Error detected. Please check that your romfs are valid!")
                if os.path.exists(self.out_dir): # delete files if user canceled
                    shutil.rmtree(self.out_dir, ignore_errors=True)
                self.done = True
            else:
                self.ui.label.setText("Canceling...")
                if os.path.exists(self.out_dir): # delete files if user canceled
                    shutil.rmtree(self.out_dir, ignore_errors=True)
                self.done = True
                self.close()



    # override the window close event to close the randomization thread
    def closeEvent(self, event):
        if not self.done:
            event.ignore()
            self.cancel = True
            self.ui.label.setText('Canceling...')
            # self.ui.label_2.setText('')
            if self.current_job == 'shuffler':
                self.shuffler_process.stop()
            elif self.current_job == 'modgenerator':
                self.mods_process.stop()
        else:
            event.accept()
