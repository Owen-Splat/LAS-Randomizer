import os
import platform
import appdirs


# this is for bundling files into a single exe with pyinstaller
try:
    from sys import _MEIPATH
    ROOT_PATH = _MEIPATH
    IS_RUNNING_FROM_SOURCE = False
    if platform.system() == "Darwin":
        userdata_path = appdirs.user_data_dir("LAS-Randomizer", "LAS-Randomizer")
        if not os.path.isdir(userdata_path):
            os.mkdir(userdata_path)
        SETTINGS_PATH = os.path.join(userdata_path, "settings.yaml")
    else:
        SETTINGS_PATH = os.path.join(".", "settings.yaml")
except ImportError:
    ROOT_PATH = os.path.dirname(os.path.realpath(__file__))
    SETTINGS_PATH = os.path.join(ROOT_PATH, "settings.yaml")
    IS_RUNNING_FROM_SOURCE = True

DATA_PATH = os.path.join(ROOT_PATH, 'Data')
RESOURCE_PATH = os.path.join(ROOT_PATH, 'Resources')
