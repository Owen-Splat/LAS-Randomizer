from PySide6 import QtCore
import urllib.request as lib

from RandomizerCore.randomizer_data import VERSION, LOGIC_VERSION



class UpdateProcess(QtCore.QThread):
    can_update = QtCore.Signal(bool)
    give_version = QtCore.Signal(float)
    

    def __init__(self, parent=None):
        QtCore.QThread.__init__(self, parent)
    
    
    def run(self):
        try:
            update_file =\
                lib.urlopen("https://raw.githubusercontent.com/Owen-Splat/LAS-Randomizer/master/version.txt")
            web_version = float(update_file.read().strip())
            
            if web_version > VERSION:
                self.give_version.emit(web_version)
                self.can_update.emit(True)
            else:
                self.can_update.emit(False)
        
        except Exception:
            self.can_update.emit(False)



class LogicUpdateProcess(QtCore.QThread):
    can_update = QtCore.Signal(bool)
    give_logic = QtCore.Signal(tuple)
    
    
    def __init__(self, parent=None, ver=LOGIC_VERSION):
        QtCore.QThread.__init__(self, parent)
        self.ver = ver
    
    
    def run(self):
        try:
            update_file =\
                lib.urlopen("https://raw.githubusercontent.com/Owen-Splat/LAS-Randomizer/master/RandomizerCore/Data/logic.yml")
            web_version = float(update_file.readline().decode('utf-8').strip('#'))
            new_logic = update_file.read().decode('utf-8')

            if web_version > self.ver:
                self.give_logic.emit((web_version, new_logic))
                self.can_update.emit(True)
            else:
                self.can_update.emit(False)
        
        except Exception:
            self.can_update.emit(False)
