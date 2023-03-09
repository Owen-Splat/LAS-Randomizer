#!/usr/bin/env python3

from PySide6 import QtCore, QtGui, QtWidgets
import UI.main_window as window
from randomizer_paths import RESOURCE_PATH

import os
import sys


def interruptHandler(sig, frame):
    sys.exit(0)

# Allow keyboard interrupts
import signal
signal.signal(signal.SIGINT, interruptHandler)


# Test if code is being ran from a build, and if not, set app id so the custom taskbar icon will show while running from source
try:
    from sys import _MEIPASS
except ImportError:
    from ctypes import windll
    try:
        windll.shell32.SetCurrentProcessExplicitAppUserModelID("Link's_Awakening_Switch_Randomizer")
    except AttributeError:
        pass # Ignore for versions of Windows before Windows 7

app = QtWidgets.QApplication([])
app.setStyle('cleanlooks')
app.setWindowIcon(QtGui.QIcon(os.path.join(RESOURCE_PATH, 'LASR_Icon.ico')))

m = window.MainWindow()

# for keyboard interrupts
timer = QtCore.QTimer()
timer.start(100)
timer.timeout.connect(lambda: None)

sys.exit(app.exec())
