#!/usr/bin/env python3

from PySide6 import QtGui, QtWidgets
import UI.main_window as window
from randomizer_paths import RESOURCE_PATH

import os
import sys


# Test if code is being ran from a build, and if not, set app id so the custom taskbar icon will show while running from source
try:
    from sys import _MEIPASS
except ImportError:
    import ctypes
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Link's_Awakening_Switch_Randomizer")
    except AttributeError:
        pass # Ignore for versions of Windows before Windows 7

app = QtWidgets.QApplication([])
app.setStyle('Fusion')
app.setWindowIcon(QtGui.QIcon(os.path.join(RESOURCE_PATH, 'LASR_Icon.ico')))

m = window.MainWindow()
sys.exit(app.exec())
