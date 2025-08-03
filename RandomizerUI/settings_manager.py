from RandomizerCore.randomizer_data import *
from pathlib import Path
import yaml, base64, copy, random


BASE_OPTIONS = {
    'ChestsCheck': True,
    'GiftsCheck': True,
    'TradeCheck': False,
    'LeavesCheck': True,
    'HeartsCheck': True,
    'ShellsCheck': True,
    'MiscCheck': True,
    'MansionBox': 2,
    'BossCheck': True,
    'InstrumentsCheck': False,
    'ShopCheck': True,
    'RupeesCheck': False,
    'OwlsBox': 0,
    'DampeCheck': False,
    'RapidsCheck': False,
    'FishingCheck': False,
    'TrendyCheck': False,
    'SpoilerCheck': True,
    'RaceCheck': False,
    'EnemyCheck': False,
    'EnemySizesCheck': False,
    'ChestTypeBox': 0,
    'KanaletCheck': True,
    'MabeCheck': False,
    'MamuCheck': True,
    'BridgeCheck': True,
    'D2Check': False,
    'DungeonsCheck': False,
    'ConsumableCheck': True, # Helps beginner players not run into the issue of being too low on resources
    'PetsCheck': False,
    'FastFishingCheck': False,
    # 'unlockedBombsCheck': True,
    'BombsCheck': False,
    'BookCheck': True,
    'StalfosCheck': False,
    'PowderCheck': False,
    'BossAnimCheck': True,
    'ChestAnimCheck': True,
    'KeyAnimCheck': True,
    'SongAnimCheck': False,
    'ItemAnimCheck': True,
    'MoveSpeedCheck': False,
    'DungeonItemsBox': 0, # Dungeon items will appear in their respective dungeons
    'ItemPoolBox': 0,
    'TrapBox': 0,
    'DamageBox': 0,
    # 'ohkoCheck': False,
    'StartHeartBox': 3,
    'MaxHeartBox': 20,
    'ControlBox': 0,
    'StealingBox': 0, # May change, but players often feel frustrated at not being able to steal, not knowing sword is needed
    # 'stealingCheck': # fast stealing always on in newer versions? TBD
    'SuperWeaponsCheck': True,
    # 'lv1BeamCheck': False,
    # 'niceRodCheck': True,
    # 'niceBombsCheck': False,
    'InstrumentStartBox': 0,
    'DungeonStartItemsBox': 3, # Beginner setting to start with map, compass, beak
    'RupeeBox': 0,
    'LogicBox': 0,
    # 'BlurCheck': True, # May change, lots of people hate the blur and it even hurts some player's eyes
    # 'MusicCheck': False,
    # 'SoundCheck': False,
    # 'BeepCheck': False,
    'starting_gear': ['sword', 'shield', 'ocarina', 'song-mambo']
}

EXTRA_OPTIONS = [
    'theme',
    'romfs_folder',
    'output_folder',
    'seed',
    'platform',
]

STRING_EXCLUSIONS = [
    'MusicCheck',
    'BlurCheck',
]

CHECK_LOCATIONS = {
    'ChestsCheck': MISCELLANEOUS_CHESTS,
    'GiftsCheck': FREE_GIFT_LOCATIONS,
    'TradeCheck': TRADE_GIFT_LOCATIONS,
    'LeavesCheck': LEAF_LOCATIONS,
    'HeartsCheck': HEART_PIECE_LOCATIONS,
    'ShellsCheck': SEASHELL_LOCATIONS,
    'MiscCheck': MISC_LOCATIONS,
    'BossCheck': BOSS_LOCATIONS,
    'ShopCheck': SHOP_ITEMS,
    'RupeesCheck': BLUE_RUPEES,
    'DampeCheck': DAMPE_REWARDS,
    'RapidsCheck': RAPIDS_REWARDS,
    'FishingCheck': FISHING_REWARDS,
    'TrendyCheck': TRENDY_REWARDS,
}


class MyDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, indentless)


def applyDefaults(window):
    for k,v in BASE_OPTIONS.items():
        match v:
            case bool():
                window.ui.findCheckBox(k).setChecked(v)
            case int():
                box = window.ui.findComboBox(k)
                if box != None:
                    box.setCurrentIndex(v)
                else:
                    window.ui.findSpinBox(k).setValue(v)
            case _:
                exec(f"window.{k} = v")
    
    window.excluded_checks.difference_update(MISCELLANEOUS_CHESTS)
    window.excluded_checks.update(FISHING_REWARDS)
    window.excluded_checks.update(RAPIDS_REWARDS)
    window.excluded_checks.update(DAMPE_REWARDS)
    window.excluded_checks.update(TRENDY_REWARDS)
    window.excluded_checks.difference_update(SHOP_ITEMS)
    window.excluded_checks.difference_update(FREE_GIFT_LOCATIONS)
    window.excluded_checks.update(TRADE_GIFT_LOCATIONS)
    window.excluded_checks.difference_update(BOSS_LOCATIONS)
    window.excluded_checks.difference_update(MISC_LOCATIONS)
    window.excluded_checks.difference_update(HEART_PIECE_LOCATIONS)
    window.excluded_checks.difference_update(SEASHELL_LOCATIONS)
    window.excluded_checks.difference_update(BLUE_RUPEES)
    window.updateSeashells()
    window.updateOwls()
    window.excluded_checks.difference_update(LEAF_LOCATIONS)
    window.tabChanged()


def saveSettings(window, for_string=False):
    settings_dict = {
        'theme': window.ui.theme,
        'romfs_folder': window.ui.findLineEdit("RomfsLine").text(),
        'output_folder': window.ui.findLineEdit("OutputLine").text(),
        'seed': window.ui.findLineEdit("SeedLine").text(),
        'platform': PLATFORMS[window.ui.findComboBox("PlatformBox").currentIndex()],
    }

    ldict = locals() # needed to be able to get the new variable value from exec
    for k,v in BASE_OPTIONS.items():
        match v:
            case bool():
                settings_dict[k] = window.ui.findCheckBox(k).isChecked()
            case int():
                box = window.ui.findComboBox(k)
                if box != None:
                    settings_dict[k] = box.currentIndex()
                else:
                    settings_dict[k] = window.ui.findSpinBox(k).value()
            case _:
                exec(f"v = window.{k}", globals(), ldict)
                settings_dict[k] = ldict['v']

    # for k,v in BASE_OPTIONS.items():
    #     if isinstance(v, bool):
    #         exec(f"v = window.ui.{k}.isChecked()", globals(), ldict)
    #     elif isinstance(v, int):
    #         if k.endswith('ComboBox'):
    #             exec(f"v = window.ui.{k}.currentIndex()", globals(), ldict)
    #         else:
    #             exec(f"v = window.ui.{k}.value()", globals(), ldict)
    #     else:
    #         exec(f"v = window.{k}", globals(), ldict)
    #     settings_dict[k] = ldict['v']
    
    settings_dict['excluded_locations'] = list(window.excluded_checks)

    if for_string:
        return settings_dict
    
    with open(SETTINGS_PATH, 'w') as f:
        yaml.dump(settings_dict, f, Dumper=MyDumper, sort_keys=False)


def loadSettings(window, settings_dict=SETTINGS):
    all_options = [k for k,v in BASE_OPTIONS.items()]
    all_options.extend(EXTRA_OPTIONS)
    
    for k,v in settings_dict.items():
        if k not in all_options:
            continue
        match v:
            case bool():
                window.ui.findCheckBox(k).setChecked(v)
            case int():
                box = window.ui.findComboBox(k)
                if box != None:
                    box.setCurrentIndex(v)
                else:
                    window.ui.findSpinBox(k).setValue(v)
        # try:
        #     if isinstance(v, bool):
        #         exec(f"window.ui.{k}.setChecked({v})")
        #     elif isinstance(v, int):
        #         if k.endswith('ComboBox'):
        #             exec(f"window.ui.{k}.setCurrentIndex({v})")
        #         else:
        #             exec(f"window.ui.{k}.setValue({v})")
        # except:
        #     pass

    if 'theme' in settings_dict:
        if settings_dict['theme'].lower() in ('light', 'dark', 'diamond-black'):
            window.ui.theme = str(settings_dict['theme'].lower())
    if 'romfs_folder' in settings_dict:
        if Path(settings_dict['romfs_folder']).exists():
            window.ui.findLineEdit("RomfsLine").setText(settings_dict['romfs_folder'])
    if 'output_folder' in settings_dict:
        if Path(settings_dict['output_folder']).exists():
            window.ui.findLineEdit("OutputLine").setText(settings_dict['output_folder'])
    if 'seed' in settings_dict:
        window.ui.findLineEdit("SeedLine").setText(settings_dict['seed'])
    try:
        window.ui.findComboBox("PlatformBox").setCurrentIndex(PLATFORMS.index(settings_dict['platform'].lower().strip()))
    except (KeyError, TypeError, IndexError, ValueError):
        window.ui.findComboBox("PlatformBox").setCurrentIndex(0)
    try:
        window.excluded_checks = set()
        for check in settings_dict['excluded_locations']:
            if check in TOTAL_CHECKS:
                window.excluded_checks.add(check)
    except (KeyError, TypeError):
        for k,v in CHECK_LOCATIONS.items():
            if not window.ui.findCheckBox(k).isChecked():
                window.excluded_checks.update(v)
        # if not window.ui.chestsCheck.isChecked():
        #     window.excluded_checks.update(MISCELLANEOUS_CHESTS)
        # if not window.ui.fishingCheck.isChecked():
        #     window.excluded_checks.update(FISHING_REWARDS)
        # if not window.ui.rapidsCheck.isChecked():
        #     window.excluded_checks.update(RAPIDS_REWARDS)
        # if not window.ui.dampeCheck.isChecked():
        #     window.excluded_checks.update(DAMPE_REWARDS)
        # if not window.ui.giftsCheck.isChecked():
        #     window.excluded_checks.update(FREE_GIFT_LOCATIONS)
        # if not window.ui.tradeGiftsCheck.isChecked():
        #     window.excluded_checks.update(TRADE_GIFT_LOCATIONS)
        # if not window.ui.bossCheck.isChecked():
        #     window.excluded_checks.update(BOSS_LOCATIONS)
        # if not window.ui.miscellaneousCheck.isChecked():
        #     window.excluded_checks.update(MISC_LOCATIONS)
        # if not window.ui.heartsCheck.isChecked():
        #     window.excluded_checks.update(HEART_PIECE_LOCATIONS)
        # if not window.ui.leavesCheck.isChecked():
        #     window.excluded_checks.update(LEAF_LOCATIONS)
        # if not window.ui.trendyCheck.isChecked():
        #     window.excluded_checks.update(TRENDY_REWARDS)
        # if not window.ui.shopCheck.isChecked():
        #     window.excluded_checks.update(SHOP_ITEMS)
    try:
        window.starting_gear = []
        for item in settings_dict['starting_gear']:
            if item in STARTING_ITEMS:
                if window.starting_gear.count(item) < STARTING_ITEMS.count(item):
                    window.starting_gear.append(item)
    except (KeyError, TypeError):
        window.starting_gear = list() # reset starting gear to default if error


def encodeSettings(window) -> str:
    """Encodes the current randomizer settings as a settings string"""

    settings_dict = saveSettings(window, for_string=True)
    settings_str = b''
    settings_str += settings_dict['seed'].encode('ascii') + b'\0'

    bool_bytes = []
    int_bytes = []
    list_bytes = []
    bool_bits = []
    list_bits = []

    for k,v in settings_dict.items():
        if k in STRING_EXCLUSIONS:
            continue
        match v:
            case bool():
                bool_bits.append(int(v))
                if len(bool_bits) == 8:
                    bool_bytes.append(bitsToInt(bool_bits))
            case int():
                int_bytes.append(v)
            case list():
                if k == 'starting_gear':
                    comp = sorted(STARTING_ITEMS)
                elif k == 'excluded_locations':
                    comp = sorted(TOTAL_CHECKS)
                settings_list = list(copy.deepcopy(settings_dict[k]))
                for c in comp:
                    list_bits.append(1 if c in settings_list else 0)
                    if list_bits[-1] == 1:
                        settings_list.remove(c)
                    if len(list_bits) == 8:
                        list_bytes.append(bitsToInt(list_bits))
                if list_bits: # flush bits to byte after list is done so that they don't mix
                    list_bytes.append(bitsToInt(list_bits))
    
    if bool_bits:
        bool_bytes.append(bitsToInt(bool_bits))
    
    for b in bool_bytes:
        settings_str += b.to_bytes(1, 'big', signed=False)
    for i,b in enumerate(int_bytes):
        num = 1
        if i == len(int_bytes)-1:
            num = 2
        settings_str += b.to_bytes(num, 'big', signed=False)
    for b in list_bytes:
        settings_str += b.to_bytes(1, 'big', signed=False)
    
    settings_str = base64.b64encode(settings_str).decode("ascii")
    return settings_str


def decodeSettings(settings_str: str) -> dict:
    "Decodes the settings string and returns a dictionary of the new settings"

    settings_str = settings_str.encode('ascii')
    settings_bytes = base64.b64decode(settings_str)
    new_settings = {}
    
    seed = readString(settings_bytes, 0)
    new_settings['seed'] = seed

    total_bytes = []
    for b in settings_bytes[len(seed)+1:]:
        total_bytes.append(b)
    
    check_boxes = []
    nums_options = []
    items = sorted(list(copy.deepcopy(STARTING_ITEMS)))
    locs = sorted(list(copy.deepcopy(TOTAL_CHECKS)))

    for k,v in BASE_OPTIONS.items():
        if k in STRING_EXCLUSIONS:
            continue
        if isinstance(v, bool):
            check_boxes.append(k)
        elif isinstance(v, int):
            nums_options.append(k)
    
    check_boxes = optionsToBitList(check_boxes)
    items = optionsToBitList(items)
    locs = optionsToBitList(locs)

    for checks in check_boxes:
        bits = intToBits(total_bytes.pop(0))
        for i,check in enumerate(checks):
            new_settings[check] = bool(bits[i])
    for check in nums_options:
        if check != 'RupeeBox':
            new_settings[check] = total_bytes.pop(0)
            continue

        n1 = total_bytes.pop(0)
        n2 = total_bytes.pop(0)
        new_settings[check] = (n1 << 8) + n2
    
    new_settings['starting_gear'] = []
    for gear in items:
        bits = intToBits(total_bytes.pop(0))
        sgear = [k for i,k in enumerate(gear) if bits[i] == 1]
        new_settings['starting_gear'].extend(sgear)
    
    new_settings['excluded_locations'] = []
    for loc in locs:
        bits = intToBits(total_bytes.pop(0))
        llist = [k for i,k in enumerate(loc) if bits[i] == 1]
        new_settings['excluded_locations'].extend(llist)
    
    return new_settings


def randomizeSettings(window):
    settings_dict = saveSettings(window, for_string=True)
    
    ldict = locals()
    for k,v in BASE_OPTIONS.items():
        match v:
            case bool():
                settings_dict[k] = bool(random.randint(0, 1))
            case int():
                box = window.ui.findComboBox(k)
                if box != None:
                    v = box.count() - 1
                    settings_dict[k] = random.randint(0, v)
                else:
                    v = window.ui.findSpinBox(k).maximum()
                    settings_dict[k] = min(random.randint(0, v), random.randint(0, v))
        # elif isinstance(v, list):
        #     if k != 'starting_gear':
        #         continue
        #     comp = STARTING_ITEMS
        #     settings_dict[k] = []
        #     for c in comp:
        #         if random.randint(0, 24) == 24: # 4% chance for each item to be added
        #             settings_dict[k].append(c)
    
    return settings_dict


def loadRandomizerSettings(window, seed):
    """Loads the necessary mod settings for the randomizer"""

    mod_settings = {
        'seed': seed,
        'logic': LOGIC_PRESETS[window.ui.findComboBox("LogicBox").currentIndex()],
        'platform': PLATFORMS[window.ui.findComboBox("PlatformBox").currentIndex()],
        'create-spoiler': window.ui.findCheckBox("SpoilerCheck").isChecked(),
        'free-book': window.ui.bookCheck.isChecked(),
        'extended-consumable-drop': window.ui.extendedConsumableCheck.isChecked(),
        'dungeon-items': DUNGEON_ITEM_SETTINGS[window.ui.dungeonItemsComboBox.currentIndex()],
        'unlocked-bombs': window.ui.unlockedBombsCheck.isChecked(),
        'shuffle-bombs': window.ui.shuffledBombsCheck.isChecked(),
        'shuffle-powder': window.ui.shuffledPowderCheck.isChecked(),
        'fast-fishing': window.ui.fastFishingCheck.isChecked(),
        'fast-stealing': window.ui.stealingCheck.isChecked(),
        'fast-songs': window.ui.songsCheck.isChecked(),
        'shuffle-instruments': window.ui.instrumentCheck.isChecked(),
        'starting-instruments': window.ui.instrumentsComboBox.currentIndex(),
        'bad-pets': window.ui.badPetsCheck.isChecked(),
        'open-kanalet': window.ui.kanaletCheck.isChecked(),
        'open-bridge': window.ui.bridgeCheck.isChecked(),
        'open-mamu': window.ui.mazeCheck.isChecked(),
        'traps': TRAP_SETTINGS[window.ui.trapsComboBox.currentIndex()],
        'blupsanity': window.ui.rupCheck.isChecked(),
        'classic-d2': window.ui.swampCheck.isChecked(),
        'owl-overworld-gifts': window.overworld_owls,
        'owl-dungeon-gifts': window.dungeon_owls,
        # 'owl-hints': True if OWLS_SETTINGS[window.ui.owlsComboBox.currentIndex()] in ['hints', 'hybrid'] else False,
        'fast-stalfos': window.ui.stalfosCheck.isChecked(),
        'chest-aspect': CHEST_ASPECT_SETTINGS[window.ui.chestAspectComboBox.currentIndex()],
        'seashells-important': True if len([s for s in SEASHELL_REWARDS if s not in window.excluded_checks]) > 0 else False,
        'trade-important': True if len([t for t in TRADE_GIFT_LOCATIONS if t not in window.excluded_checks]) > 0 else False,
        # 'shuffle-companions': window.ui.companionCheck.isChecked(),
        # 'randomize-entrances': window.ui.loadingCheck.isChecked(),
        'randomize-music': window.ui.musicCheck.isChecked(),
        'open-mabe': window.ui.openMabeCheck.isChecked(),
        'boss-cutscenes': window.ui.bossCutscenesCheck.isChecked(),
        'randomize-enemies': window.ui.enemyCheck.isChecked(),
        'randomize-enemy-sizes': window.ui.enemySizesCheck.isChecked(),
        # 'panel-enemies': True if len([s for s in DAMPE_REWARDS if s not in window.excluded_checks]) > 0 else False,
        'shuffle-dungeons': window.ui.dungeonsCheck.isChecked(),
        # 'keysanity': DUNGEON_ITEM_SETTINGS[window.ui.itemsComboBox.currentIndex()],
        'blur-removal': window.ui.blurCheck.isChecked(),
        'OHKO': window.ui.ohkoCheck.isChecked(),
        'lv1-beam': window.ui.lv1BeamCheck.isChecked(),
        'nice-rod': window.ui.niceRodCheck.isChecked(),
        'nice-bombs': window.ui.niceBombsCheck.isChecked(),
        'stealing': STEALING_REQUIREMENTS[window.ui.stealingComboBox.currentIndex()],
        'fast-chests': window.ui.chestAnimationsCheck.isChecked(),
        'fast-keys': window.ui.keyAnimationsCheck.isChecked(),
        'starting-items': window.starting_gear,
        'starting-rupees': window.ui.rupeesSpinBox.value(),
        'excluded-locations': window.excluded_checks
    }
    return mod_settings


def bitsToInt(bits: list) -> int:
    """Reads a list of bits in big endian and converts it into an unsigned integer"""

    while len(bits) < 8:
        bits.append(0)
    bits.reverse() # reverse bit order since base64 is big endian
    bin_str = ''.join(str(i) for i in bits)
    bits[:] = []
    return int(bin_str, 2)


def intToBits(num) -> list:
    """Takes an unsigned integer and converts it into a list of bits in big endian"""

    bits = []
    f = 1
    for i in range(8):
        bits.append(1 if num&f != 0 else 0)
        f *= 2
    
    return bits


def optionsToBitList(options) -> list:
    """Takes a list and breaks it into lists of 8"""

    new_options = []
    start = 0
    end = len(options) 
    step = 8
    for i in range(start, end, step): 
        x = i 
        new_options.append(options[x:x+step])
    
    return new_options


def readString(data, start):
    """Returns an ascii encoded string from bytes"""

    result = b''
    index = start
    while index < len(data) and data[index]:
        result += data[index : index + 1]
        index += 1
    
    result = str(result, 'ascii')
    return result
