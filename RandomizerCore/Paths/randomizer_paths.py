import os
import sys
import appdirs
import platform

if getattr(sys, "frozen", False):
    # application is frozen
    ROOT_PATH = os.path.dirname(sys.executable)
    IS_RUNNING_FROM_SOURCE = False
    if platform.system() == 'Darwin':
        userdata_path = appdirs.user_data_dir('randomizer', 'LAS Randomizer')
        if not os.path.isdir(userdata_path):
            os.mkdir(userdata_path)
        SETTINGS_PATH = os.path.join(userdata_path, 'settings.txt')
        LOGS_PATH = os.path.join(userdata_path, 'log.txt')
    else:
        SETTINGS_PATH = os.path.join('.', 'settings.txt')
        LOGS_PATH = os.path.join('.', 'log.txt')
else:
    # application is not frozen
    ROOT_PATH = os.path.dirname(__file__)
    SETTINGS_PATH = os.path.join(ROOT_PATH, 'settings.txt')
    LOGS_PATH = os.path.join(ROOT_PATH, 'log.txt')
    IS_RUNNING_FROM_SOURCE = True

DATA_PATH = os.path.join(ROOT_PATH, 'Data')
RESOURCE_PATH = os.path.join(ROOT_PATH, 'Resources')
LOGIC_PATH = os.path.join(DATA_PATH, 'logic.yml')