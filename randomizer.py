#!/usr/bin/env python3

from PySide6 import QtGui, QtWidgets
import UI.main_window as window
from randomizer_paths import RESOURCE_PATH

import os
import sys



def main():
    
    try:
        from sys import _MEIPASS
    except ImportError:
        import ctypes
        try:
            # Need to set app id so windows will display the custom taskbar icon while running from source
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Link's_Awakening_Switch_Randomizer")
        except AttributeError:
            pass
    
    app = QtWidgets.QApplication([])
    app.setStyle('Fusion')
    
    icon = QtGui.QIcon()
    icon.addPixmap(QtGui.QPixmap(os.path.join(RESOURCE_PATH, 'LASR_Icon.png')), QtGui.QIcon.Mode.Normal, QtGui.QIcon.State.Off)
    app.setWindowIcon(icon)
    
    m = window.MainWindow()
    m.setFixedSize(780, 639)
    m.show()
    
    sys.exit(app.exec())



if __name__ == '__main__':
    main()