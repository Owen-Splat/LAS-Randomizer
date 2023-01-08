from PySide6 import QtCore
import urllib.request as lib
import urllib.error as urlERROR

from randomizer_data import VERSION



class UpdateProcess(QtCore.QThread):
    
    can_update = QtCore.Signal(bool)
    
    
    # initialize
    def __init__(self, parent=None):
        QtCore.QThread.__init__(self, parent)
    
    
    def run(self):
        try:
            update_file =\
                lib.urlopen("https://raw.githubusercontent.com/Owen-Splat/LAS-Randomizer/experimental/version.txt")
            web_version = float(update_file.read().strip())
            
            if web_version > VERSION:
                self.can_update.emit(True)
            else:
                self.can_update.emit(False)
        
        except urlERROR.URLError: # when users use this app while not connected to the internet
            self.can_update.emit(False)
