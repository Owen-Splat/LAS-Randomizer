from PySide6 import QtCore
import urllib.request as lib
import urllib.error as urlERROR

from randomizer_data import LOGIC_VERSION



class LogicUpdateProcess(QtCore.QThread):
    
    can_update = QtCore.Signal(bool)
    give_logic = QtCore.Signal(tuple)
    
    # initialize
    def __init__(self, parent=None):
        QtCore.QThread.__init__(self, parent)
    
    
    def run(self):
        try:
            update_file =\
                lib.urlopen("https://raw.githubusercontent.com/Owen-Splat/LAS-Randomizer/master/Data/logic.yml")
            web_version = float(update_file.readline().decode('utf-8').strip('#'))
            new_logic = update_file.read().decode('utf-8')

            if web_version > LOGIC_VERSION:
                self.give_logic.emit((web_version, new_logic))
                self.can_update.emit(True)
            else:
                self.can_update.emit(False)
        
        except urlERROR.URLError: # when users use this app while not connected to the internet
            self.can_update.emit(False)
