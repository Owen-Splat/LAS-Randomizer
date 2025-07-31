from pathlib import Path
import appdirs, platform, sys

# check if user is running a precompiled binary
if getattr(sys, "frozen", False):
    IS_RUNNING_FROM_SOURCE = False
    ROOT_PATH = Path(sys.executable).parent
    ASM_PATH = ROOT_PATH / 'lib/RandomizerCore/ASM/Patches'
    DATA_PATH = ROOT_PATH / 'Data'
    RESOURCE_PATH = ROOT_PATH / 'Resources'
    if platform.system() == 'Darwin':
        userdata_path = Path(appdirs.user_data_dir('randomizer', 'LAS Randomizer'))
        if not userdata_path.is_dir():
            userdata_path.mkdir(parents=True, exist_ok=True)
        SETTINGS_PATH = userdata_path / 'settings.txt'
        LOGS_PATH = userdata_path / 'log.txt'
    else:
        SETTINGS_PATH = ROOT_PATH / 'settings.txt'
        LOGS_PATH = ROOT_PATH / 'log.txt'
else:
    IS_RUNNING_FROM_SOURCE = True
    ROOT_PATH = Path(sys.argv[0]).parent
    ASM_PATH = ROOT_PATH / 'RandomizerCore' / 'ASM' / 'Patches'
    DATA_PATH = ROOT_PATH / 'RandomizerCore' / 'Data'
    RESOURCE_PATH = ROOT_PATH / 'RandomizerUI' / 'Resources'
    SETTINGS_PATH = ROOT_PATH / 'settings.txt'
    LOGS_PATH = ROOT_PATH / 'log.txt'

LOGIC_PATH = DATA_PATH / 'logic.yml'
