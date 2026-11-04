from RandomizerCore.Paths.randomizer_paths import DATA_PATH, RESOURCE_PATH, SETTINGS_PATH, LOGIC_PATH

import yaml
import os

VERSION = 0.41

DOWNLOAD_PAGE = 'https://github.com/Owen-Splat/LAS-Randomizer/releases/latest'

with open(os.path.join(RESOURCE_PATH, 'light_theme.txt'), 'r') as data_file:
    LIGHT_STYLESHEET = data_file.read()

with open(os.path.join(RESOURCE_PATH, 'dark_theme.txt'), 'r') as data_file:
    DARK_STYLESHEET = data_file.read()

with open(os.path.join(RESOURCE_PATH, 'changes.txt'), 'r') as data_file:
    CHANGE_LOG = data_file.read()

with open(os.path.join(RESOURCE_PATH, 'issues.txt'), 'r') as data_file:
    KNOWN_ISSUES = data_file.read()

with open(os.path.join(RESOURCE_PATH, 'tips.txt'), 'r') as data_file:
    HELPFUL_TIPS = data_file.read()

with open(os.path.join(RESOURCE_PATH, 'about.txt'), 'r') as data_file:
    ABOUT_INFO = data_file.read()

with open(os.path.join(DATA_PATH, 'items.yml'), 'r') as data_file:
    item_data = yaml.safe_load(data_file)
    ITEM_DEFS = item_data['Item_Pool']
    STARTING_ITEMS = list(item_data['Starting_Items'])

with open(LOGIC_PATH, 'r') as data_file:
    LOGIC_VERSION = float(data_file.readline().strip('#'))
    LOGIC_RAW = data_file.read()
    # LOGIC_DEFS = yaml.safe_load(f)
    # TRICKS = [k for k, v in LOGIC_DEFS.items() if v['type'] == 'trick']

with open(os.path.join(DATA_PATH, 'enemies.yml'), 'r') as data_file:
    ENEMY_DATA = yaml.safe_load(data_file)

with open(os.path.join(DATA_PATH, 'locations.yml'), 'r') as data_file:
    LOCATIONS = yaml.safe_load(data_file)

with open(os.path.join(RESOURCE_PATH, 'adjectives.txt'), 'r') as data_file:
    ADJECTIVES = data_file.read().splitlines()

with open(os.path.join(RESOURCE_PATH, 'characters.txt'), 'r') as data_file:
    CHARACTERS = data_file.read().splitlines()

try:
    with open(SETTINGS_PATH, 'r') as settings_file:
        SETTINGS = yaml.safe_load(settings_file)
        DEFAULTS = False
except FileNotFoundError:
    DEFAULTS = True
    SETTINGS = {}

MISCELLANEOUS_CHESTS = LOCATIONS['Chest_Locations']
FISHING_REWARDS = LOCATIONS['Fishing_Rewards']
RAPIDS_REWARDS = LOCATIONS['Rapids_Rewards']
DAMPE_REWARDS = LOCATIONS['Dampe_Rewards']
SHOP_ITEMS = LOCATIONS['Shop_Items']
TRENDY_REWARDS = LOCATIONS['Trendy_Rewards']
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

# Indexed shell locations share the standalone pickup adapter.
SHELL_LOCATIONS = [location_name for location_name,location_details in yaml.safe_load(LOGIC_RAW).items() if location_details.get('type') == 'item' and location_details.get('content') == 'seashell' and location_details.get('subtype') in ('dig','hidden','bomb-hole','underwater')]

# Include every category that can appear in the location settings.
TOTAL_CHECKS = set([
    *MISCELLANEOUS_CHESTS, *FISHING_REWARDS, *RAPIDS_REWARDS,
    *DAMPE_REWARDS, *FREE_GIFT_LOCATIONS, *TRADE_GIFT_LOCATIONS,
    *BOSS_LOCATIONS, *MISC_LOCATIONS, *SEASHELL_REWARDS,
    *HEART_PIECE_LOCATIONS, *LEAF_LOCATIONS, *DUNGEON_OWLS,
    *OVERWORLD_OWLS, *BLUE_RUPEES, *SHOP_ITEMS, *TRENDY_REWARDS, *SHELL_LOCATIONS
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
