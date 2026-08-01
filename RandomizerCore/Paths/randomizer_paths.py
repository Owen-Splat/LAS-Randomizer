from pathlib import Path
import appdirs, platform, sys

# check if user is running a precompiled binary
try:
    from sys import _MEIPASS
    IS_RUNNING_FROM_SOURCE = False
    ROOT_PATH = Path(_MEIPASS)
    if platform.system() == 'Darwin': # mac
        userdata_path = Path(appdirs.user_data_dir('randomizer', 'LAS Randomizer'))
        if not userdata_path.exists():
            userdata_path.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH = userdata_path / 'settings.txt'
        LOGS_PATH = userdata_path / 'log.txt'
        EXL_PATH = userdata_path / 'exl'
    else:
        SETTINGS_PATH = Path() / 'settings.txt'
        LOGS_PATH = Path() / 'log.txt'
        EXL_PATH = Path() / 'exl'
except ImportError:
    IS_RUNNING_FROM_SOURCE = True
    ROOT_PATH = Path(sys.argv[0]).parent.absolute()
    SETTINGS_PATH = ROOT_PATH / 'settings.txt'
    LOGS_PATH = ROOT_PATH / 'log.txt'
    EXL_PATH = ROOT_PATH / 'exl'

DATA_PATH = ROOT_PATH / 'RandomizerCore' / 'Data'
RESOURCE_PATH = ROOT_PATH / 'RandomizerUI' / 'Resources'
VERSION_PATH = ROOT_PATH / 'version.txt'
