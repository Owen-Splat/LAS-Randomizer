import sys
import os


# this is for bundling files into a single exe with pyinstaller
try:
    ROOT_PATH = sys._MEIPATH
except AttributeError:
    ROOT_PATH = os.path.dirname(os.path.realpath(__file__))

DATA_PATH = os.path.join(ROOT_PATH, 'Data')
RESOURCE_PATH = os.path.join(ROOT_PATH, 'Resources')
