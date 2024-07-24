from RandomizerCore.Paths.randomizer_paths import DATA_PATH, RESOURCE_PATH, SETTINGS_PATH, LOGIC_PATH

import yaml
import os

VERSION = 0.4

DOWNLOAD_PAGE = 'https://github.com/Owen-Splat/LAS-Randomizer/releases/latest'

with open(os.path.join(RESOURCE_PATH, 'light_theme.txt'), 'r') as f:
    LIGHT_STYLESHEET = f.read()

with open(os.path.join(RESOURCE_PATH, 'dark_theme.txt'), 'r') as f:
    DARK_STYLESHEET = f.read()

with open(os.path.join(RESOURCE_PATH, 'changes.txt'), 'r') as f:
    CHANGE_LOG = f.read()

with open(os.path.join(RESOURCE_PATH, 'issues.txt'), 'r') as f:
    KNOWN_ISSUES = f.read()

with open(os.path.join(RESOURCE_PATH, 'tips.txt'), 'r') as f:
    HELPFUL_TIPS = f.read()

with open(os.path.join(RESOURCE_PATH, 'about.txt'), 'r') as f:
    ABOUT_INFO = f.read()

with open(os.path.join(DATA_PATH, 'items.yml'), 'r') as f:
    items = yaml.safe_load(f)
    ITEM_DEFS = items['Item_Pool']
    STARTING_ITEMS = list(items['Starting_Items'])

with open(LOGIC_PATH, 'r') as f:
    LOGIC_VERSION = float(f.readline().strip('#'))
    LOGIC_RAW = f.read()
    # LOGIC_DEFS = yaml.safe_load(f)
    # TRICKS = [k for k, v in LOGIC_DEFS.items() if v['type'] == 'trick']

with open(os.path.join(DATA_PATH, 'enemies.yml'), 'r') as f:
    ENEMY_DATA = yaml.safe_load(f)

with open(os.path.join(DATA_PATH, 'locations.yml'), 'r') as f:
    LOCATIONS = yaml.safe_load(f)

with open(os.path.join(RESOURCE_PATH, 'adjectives.txt'), 'r') as f:
    ADJECTIVES = f.read().splitlines()

with open(os.path.join(RESOURCE_PATH, 'characters.txt'), 'r') as f:
    CHARACTERS = f.read().splitlines()

try:
    with open(SETTINGS_PATH, 'r') as settingsFile:
        SETTINGS = yaml.safe_load(settingsFile)
        DEFAULTS = False
except FileNotFoundError:
    DEFAULTS = True
    SETTINGS = {}

MISCELLANEOUS_CHESTS = LOCATIONS['Chest_Locations']
FISHING_REWARDS = LOCATIONS['Fishing_Rewards']
RAPIDS_REWARDS = LOCATIONS['Rapids_Rewards']
DAMPE_REWARDS = LOCATIONS['Dampe_Rewards']
# SHOP_ITEMS = LOCATIONS['Shop_Items']
# TRENDY_REWARDS = LOCATIONS['Trendy_Rewards']
FREE_GIFT_LOCATIONS = LOCATIONS['Free_Gifts']
TRADE_GIFT_LOCATIONS = LOCATIONS['Trade_Gifts']
BOSS_LOCATIONS = LOCATIONS['Boss_Locations']
MISC_LOCATIONS = LOCATIONS['Misc_Items']
SEASHELL_REWARDS = LOCATIONS['Mansion']
HEART_PIECE_LOCATIONS = LOCATIONS['Heart_Pieces']
LEAF_LOCATIONS = LOCATIONS['Golden_Leaves']
DUNGEON_OWLS = LOCATIONS['Dungeon_Owl_Statues']
OVERWORLD_OWLS = LOCATIONS['Overworld_Owl_Statues']
BLUE_RUPEES = LOCATIONS['Blue_Rupees']

TOTAL_CHECKS = set([
    *MISCELLANEOUS_CHESTS, *FISHING_REWARDS, *RAPIDS_REWARDS,
    *DAMPE_REWARDS, *FREE_GIFT_LOCATIONS, *TRADE_GIFT_LOCATIONS,
    *BOSS_LOCATIONS, *MISC_LOCATIONS, *SEASHELL_REWARDS,
    *HEART_PIECE_LOCATIONS, *LEAF_LOCATIONS, *DUNGEON_OWLS,
    *OVERWORLD_OWLS, *BLUE_RUPEES, #*SHOP_ITEMS, *TRENDY_REWARDS
])

SEASHELL_VALUES = (0, 5, 15, 30, 40, 50)

LOGIC_PRESETS = ('basic', 'advanced', 'glitched', 'hell', 'none')

OWLS_SETTINGS = ('none', 'overworld', 'dungeons', 'all') # ('vanilla', 'hints', 'gifts', 'hybrid')

TRAP_SETTINGS = ('none', 'few', 'several', 'many', 'trapsanity')

CHEST_ASPECT_SETTINGS = ('default', 'csmc', 'camc')

DUNGEON_ITEM_SETTINGS = ('none', 'stone-beak', 'mc', 'mcb')

# KEYSANITY_SETTINGS = ('standard', 'keys', 'keys+mcb')

PLATFORMS = ('console', 'emulator')

STEALING_REQUIREMENTS = ('always', 'never', 'normal')
