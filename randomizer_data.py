from randomizer_paths import DATA_PATH, ROOT_PATH, SETTINGS_PATH

import qdarktheme
import yaml
import os


### define constants
with open(os.path.join(ROOT_PATH, 'version.txt'), 'r') as f:
    VERSION = float(f.read().strip())

DOWNLOAD_PAGE = 'https://github.com/Owen-Splat/LAS-Randomizer/releases/latest'

LIGHT_STYLESHEET = qdarktheme.load_stylesheet('light')
DARK_STYLESHEET = qdarktheme.load_stylesheet('dark')

with open(os.path.join(DATA_PATH, 'items.yml'), 'r') as f:
    ITEM_DEFS = yaml.safe_load(f)

with open(os.path.join(DATA_PATH, 'logic.yml'), 'r') as f:
    LOGIC_DEFS = yaml.safe_load(f)
    TRICKS = [k for k, v in LOGIC_DEFS.items() if v['type'] == 'trick']

with open(os.path.join(DATA_PATH, 'enemies.yml'), 'r') as f:
    ENEMY_DATA = yaml.safe_load(f)

with open(os.path.join(DATA_PATH, 'locations.yml'), 'r') as f:
    LOCATIONS = yaml.safe_load(f)

with open(os.path.join(DATA_PATH, 'seeds.yml'), 'r') as f:
    seeds = yaml.safe_load(f)
    ADJECTIVES = seeds['Adjectives']
    CHARACTERS = seeds['Characters']

try:
    with open(SETTINGS_PATH, 'r') as settingsFile:
        SETTINGS = yaml.safe_load(settingsFile)
        DEFAULTS = False
except FileNotFoundError:
    DEFAULTS = True


# game locations
MISCELLANEOUS_CHESTS = LOCATIONS['Chest_Locations']
FISHING_REWARDS = LOCATIONS['Fishing_Rewards']
RAPIDS_REWARDS = LOCATIONS['Rapids_Rewards']
DAMPE_REWARDS = LOCATIONS['Dampe_Rewards']
TRENDY_REWARDS = LOCATIONS['Trendy_Rewards']
FREE_GIFT_LOCATIONS = LOCATIONS['Free_Gifts']
TRADE_GIFT_LOCATIONS = LOCATIONS['Trade_Gifts']
BOSS_LOCATIONS = LOCATIONS['Boss_Locations']
MISC_LOCATIONS = LOCATIONS['Misc_Items']
SEASHELL_REWARDS = LOCATIONS['Mansion']
HEART_PIECE_LOCATIONS = LOCATIONS['Heart_Pieces']

# keep track of all game locations
TOTAL_CHECKS = set([
    *MISCELLANEOUS_CHESTS, *FISHING_REWARDS, *RAPIDS_REWARDS,
    *DAMPE_REWARDS, *FREE_GIFT_LOCATIONS, *TRADE_GIFT_LOCATIONS,
    *BOSS_LOCATIONS, *MISC_LOCATIONS, *SEASHELL_REWARDS,
    *HEART_PIECE_LOCATIONS, *TRENDY_REWARDS
])

SEASHELL_VALUES = (0, 5, 15, 30, 40, 50)

LOGIC_PRESETS = ('basic', 'advanced', 'glitched', 'death', 'none')

OWLS_SETTINGS = ('none', 'overworld', 'dungeons', 'all') # ('vanilla', 'hints', 'gifts', 'hybrid')