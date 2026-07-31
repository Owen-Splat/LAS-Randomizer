from PySide6.QtWidgets import QCheckBox, QSpinBox
from RandomizerUI.UI.custom_widgets import RandoComboBox
from RandomizerUI.UI.ui_main import Ui_MainWindow
from RandomizerCore.randomizer_data import *
from pathlib import Path
import yaml, base64, copy, random, re


CHECKBOX_DEFAULTS = ( # true if in this list, false if not
    "Chests",
    "Free Gifts",
    "Golden Leaves",
    "Heart Pieces",
    "Seashells",
    "Miscellaneous",
    "Shop",
    "Boss Drops",
    # "Companions",
    "Create Spoiler Log",
    "Open Kanalet",
    "Open Mabe",
    "Open Mamu",
    "Completed Bridge",
    "Consumable Drops",
    "Fast Fishing",
    "Shuffled Bombs",
    "Free Book",
    "Fast Stalfos",
    "Shuffled Powder",
    "Boss Cutscenes",
    "Movement Speed",
    "Chest Animations",
    "Key Animations",
    # "Super Weapons"
    "Nice Bombs",
    "Nice Magic Rod"
)

SPINBOX_DEFAULTS = {
    "Rupees:  ": 100,
    "Containers:  ": 0,
    "Pieces:  ": 0
}

COMBOBOX_DEFAULTS = {
    "Seashell Mansion": 3,
    "Small Keys": 1,
    "Nightmare Keys": 1,
    "Shuffle_Instruments": 4,
    "Required Dungeons":  5,
    "Stealing": 1,
    "Traps": 2,
    "Damage": 1
}

STRING_EXCLUSIONS = (
    "Music",
    "Randomize Sound Effects",
    "Randomize Text",
    "Blur Removal",
    "Instant Text",
    "360 Movement",
    "Disable Low Health Beep",
    "Disable Guardian Acorn",
    "Disable Piece of Power"
)

DEFAULT_START_GEAR = (
    "sword",
    "shield",
    "ocarina",
    "song-mambo"
)

CHECK_LOCATIONS = {
    'Chests': MISCELLANEOUS_CHESTS,
    'Free Gifts': FREE_GIFT_LOCATIONS,
    'Trade Quest': TRADE_GIFT_LOCATIONS,
    'Golden Leaves': LEAF_LOCATIONS,
    'Heart Pieces': HEART_PIECE_LOCATIONS,
    'Seashells': SEASHELL_LOCATIONS,
    'Miscellaneous': MISC_LOCATIONS,
    'Boss Drops': BOSS_LOCATIONS,
    'Shop': SHOP_ITEMS,
    'Blue Rupees': BLUE_RUPEES,
    "Dampe": DAMPE_REWARDS,
    'Rapids': RAPIDS_REWARDS,
    'Fishing': FISHING_REWARDS,
    'Trendy Game': TRENDY_REWARDS,
}


class MyDumper(yaml.Dumper):
    def increase_indent(self, flow=False, indentless=False):
        return super(MyDumper, self).increase_indent(flow, indentless)


class SettingsManager:
    """A class for managing user settings"""

    def __init__(self, ui: Ui_MainWindow):
        self.ui = ui
        self.saving = False


    def save(self) -> None:
        """Saves the current settings to a file"""

        self.saving = True
        settings = self.fetch()
        settings["Settings"] = dict(sorted(settings["Settings"].items()))
        settings["Starting Gear"].sort()
        settings["Excluded Locations"].sort(key=alphanumericSortKey)
        with open(SETTINGS_PATH, 'w') as f:
            yaml.dump(settings, f, Dumper=MyDumper, sort_keys=False)
        self.saving = False


    def load(self, settings=SETTINGS) -> None:
        """Loads settings and applies them"""

        for k,v in settings.items():
            try:
                match k.lower().strip():
                    case "theme":
                        if settings[k].lower().strip() in ("light", "dark", "diamond-black"):
                            self.ui.theme = str(settings[k].lower().strip())
                    case "romfs":
                        romfs_path = Path(settings[k])
                        if romfs_path != Path() and romfs_path.exists():
                            self.ui.findLineEdit("RomfsLine").setText(settings[k])
                    case "output":
                        out_path = Path(settings[k])
                        if out_path != Path() and out_path.exists():
                            self.ui.findLineEdit("OutputLine").setText(settings[k])
                    case "seed":
                        seed = str(settings[k])
                        if len(seed) > 32:
                            seed = seed[:32]
                        self.ui.findLineEdit("SeedLine").setText(seed)
                    case "settings":
                        for k,v in v.items():
                            self.ui.setWidgetSetting(k, v)
            except: # if it errors we dont really care why, ignore so it is left at the default value
                continue

        try:
            self.ui.window.excluded_checks = set()
            for check in settings["Excluded Locations"]:
                check = self.ui.window.listToCheck(str(check))
                if check in TOTAL_CHECKS:
                    self.ui.window.excluded_checks.add(check)
        except (KeyError, TypeError):
            for k,v in CHECK_LOCATIONS.items():
                if not self.ui.findCheckBox(k).isChecked():
                    self.ui.window.excluded_checks.update(v)
        try:
            self.ui.window.starting_gear = []
            for item in settings["Starting Gear"]:
                item = self.ui.window.listToItem(str(item))
                if item in STARTING_ITEMS:
                    if self.ui.window.starting_gear.count(item) < STARTING_ITEMS.count(item):
                        self.ui.window.starting_gear.append(item)
        except (KeyError, TypeError):
            self.ui.window.starting_gear = list(DEFAULT_START_GEAR) # reset to default if error


    def fetch(self) -> dict:
        """Fetches the current user settings"""

        seed = self.ui.findLineEdit('SeedLine').text()
        if len(seed) > 32:
            seed = seed[:32]
        else:
            if (seed == "") and (not self.saving):
                random.seed()
                seed = str(random.getrandbits(32))

        romdir = self.ui.findLineEdit("RomfsLine").text()
        outdir = self.ui.findLineEdit("OutputLine").text()
        if not self.saving:
            romdir = Path(romdir)
            outdir = Path(outdir)

        settings = {
            "RomFS": romdir,
            "Output": outdir,
            "Seed": seed,
            "Settings": {}
        }

        settings["Settings"] = self.ui.getSettingsDict()
        starting_gear = list(self.ui.window.starting_gear)
        excluded_locations = list(self.ui.window.excluded_checks)
        if self.saving:
            starting_gear = [self.ui.window.checkToList(str(g)) for g in starting_gear]
            excluded_locations = [self.ui.window.checkToList(str(l)) for l in excluded_locations]
        settings["Starting Gear"] = starting_gear
        settings["Excluded Locations"] = excluded_locations
        return settings


    def randomize(self) -> None:
        """Randomizes the current user settings"""

        widgets = self.ui.getSettingsWidgets()

        for widget in widgets:
            match widget:
                case QCheckBox():
                    widget.setChecked(bool(random.randint(0, 1)))
                case QSpinBox():
                    widget.setValue(random.randint(widget.minimum(), widget.maximum()))
                case RandoComboBox():
                    widget.setCurrentIndex(random.randint(0, widget.count() - 1))


    def reset(self):
        """Resets settings to the defaults"""

        widgets = self.ui.getSettingsWidgets()

        for widget in widgets:
            match widget:
                case QCheckBox():
                    widget.setChecked(widget.text() in CHECKBOX_DEFAULTS)
                case QSpinBox():
                    widget.setValue(SPINBOX_DEFAULTS[widget.prefix()])
                case RandoComboBox():
                    if widget.hidden_prefix:
                        k = widget.hidden_prefix
                    else:
                        k = widget.currentText().split(':')[0]
                    if k in COMBOBOX_DEFAULTS:
                        widget.setCurrentIndex(COMBOBOX_DEFAULTS[k])
                    else:
                        widget.setCurrentIndex(0)
                case _:
                    raise TypeError("Unknown widget type when resetting settings!")

        self.ui.window.excluded_checks.difference_update(MISCELLANEOUS_CHESTS)
        self.ui.window.excluded_checks.update(FISHING_REWARDS)
        self.ui.window.excluded_checks.update(RAPIDS_REWARDS)
        self.ui.window.excluded_checks.update(DAMPE_REWARDS)
        self.ui.window.excluded_checks.update(TRENDY_REWARDS)
        self.ui.window.excluded_checks.difference_update(SHOP_ITEMS)
        self.ui.window.excluded_checks.difference_update(FREE_GIFT_LOCATIONS)
        self.ui.window.excluded_checks.update(TRADE_GIFT_LOCATIONS)
        self.ui.window.excluded_checks.difference_update(BOSS_LOCATIONS)
        self.ui.window.excluded_checks.difference_update(MISC_LOCATIONS)
        self.ui.window.excluded_checks.difference_update(HEART_PIECE_LOCATIONS)
        self.ui.window.excluded_checks.difference_update(SEASHELL_LOCATIONS)
        self.ui.window.excluded_checks.difference_update(BLUE_RUPEES)
        self.ui.window.excluded_checks.difference_update(LEAF_LOCATIONS)
        self.ui.window.starting_gear = list(DEFAULT_START_GEAR)
        self.ui.window.updateSeashells()
        self.ui.window.updateOwls()
        self.ui.window.tabChanged()


    def encode(self) -> str:
        """Encodes the current randomizer settings as a settings string"""

        settings_dict = self.fetch()
        settings_str = b''
        settings_str += settings_dict["Seed"].encode("ascii") + b'\0'

        bool_bytes = []
        int_bytes = []
        list_bytes = []
        bool_bits = []
        list_bits = []

        for k,v in settings_dict["Settings"].items():
            if k in STRING_EXCLUSIONS:
                continue
            # first convert combobox value to the index instead of text
            if self.ui.findComboBox(k) is not None:
                v = self.ui.findComboBox(k).currentIndex()
            match v:
                case bool():
                    bool_bits.append(int(v))
                    if len(bool_bits) == 8:
                        bool_bytes.append(bitsToInt(bool_bits))
                case int():
                    int_bytes.append(v)
                case list():
                    if k == "Starting Gear":
                        comp = sorted(STARTING_ITEMS)
                    elif k == "Excluded Locations":
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
            if i == len(int_bytes)-3: # starting rupees
                num = 2
            settings_str += b.to_bytes(num, 'big', signed=False)
        for b in list_bytes:
            settings_str += b.to_bytes(1, 'big', signed=False)

        settings_str = base64.b64encode(settings_str).decode("ascii")
        return settings_str


    def decode(self, settings_str: str) -> dict:
        "Decodes the settings string and returns a dictionary of the new settings"

        settings_dict = self.fetch()
        settings_str = settings_str.encode("ascii")
        settings_bytes = base64.b64decode(settings_str)
        new_settings = {}

        seed = readString(settings_bytes, 0)
        new_settings["Seed"] = seed

        total_bytes = []
        for b in settings_bytes[len(seed)+1:]:
            total_bytes.append(b)

        check_boxes = []
        nums_options = []
        items = sorted(list(copy.deepcopy(STARTING_ITEMS)))
        locs = sorted(list(copy.deepcopy(TOTAL_CHECKS)))

        for k,v in settings_dict["Settings"].items():
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
            if check != "Rupees":
                new_settings[check] = total_bytes.pop(0)
                continue

            n1 = total_bytes.pop(0)
            n2 = total_bytes.pop(0)
            new_settings[check] = (n1 << 8) + n2

        new_settings["Starting Gear"] = []
        for gear in items:
            bits = intToBits(total_bytes.pop(0))
            sgear = [k for i,k in enumerate(gear) if bits[i] == 1]
            new_settings["Starting Gear"].extend(sgear)

        new_settings["Excluded Locations"] = []
        for loc in locs:
            bits = intToBits(total_bytes.pop(0))
            llist = [k for i,k in enumerate(loc) if bits[i] == 1]
            new_settings["Excluded Locations"].extend(llist)

        return new_settings


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


def alphanumericSortKey(s):
    """Splits the string into chunks of digits and non-digits"""

    return [int(text) if text.isdigit() else text.lower() 
            for text in re.split('([0-9]+)', s)]
