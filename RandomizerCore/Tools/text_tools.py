from lms.message.msbtio import read_msbt as readMSBT
from lms.message.msbtio import write_msbt as writeMSBT
from lms.message.msbtentry import MSBTEntry
from pathlib import Path
import re, copy


class TextFile:
    COMMANDS = {
        "COLOR_WHITE":          "[0:3 ED-ED-ED-FF]",
        "COLOR_PINK":           "[0:3 D9-45-6D-FF]",
        "COLOR_ICEBLUE":        "[0:3 A0-FF-FF-FF]",
        "COLOR_GREEN":          "[0:3 63-E3-43-FF]",
        "COLOR_BLUE":           "[0:3 00-95-EF-FF]",
        "COLOR_RED":            "[0:3 DF-10-00-FF]",
        "COLOR_SKYBLUE":        "[0:3 62-CF-FF-FF]",

        "YOSHI":                "[1:0 00]",
        "RIBBON":               "[1:0 01]",
        "DOGFOOD":              "[1:0 02]",
        "BANANAS":              "[1:0 03]",
        "STICK":                "[1:0 04]",
        "HONEYCOMB":            "[1:0 05]",
        "PINEAPPLE":            "[1:0 06]",
        "HIBISCUS":             "[1:0 07]",
        "LETTER":               "[1:0 08]",
        "BROOM":                "[1:0 09]",
        "HOOK":                 "[1:0 0A]",
        "NECKLACE":             "[1:0 0B]",
        "SCALE":                "[1:0 0C]",
        "LINK":                 "[1:0 0D]",
        "MARIN":                "[1:0 0E]",
        "MARK_X":               "[1:0 0F]",
        "STALFON":              "[1:0 10]",
        "OCARINA":              "[1:0 11]",
        "ARROW_UP":             "[1:0 12]",
        "ARROW_DOWN":           "[1:0 13]",
        "ARROW_RIGHT":          "[1:0 14]",
        "ARROW_LEFT":           "[1:0 15]",

        "BUTTON_A":             "[1:2 00]",
        "BUTTON_B":             "[1:2 01]",
        "BUTTON_X":             "[1:2 04]",
        "BUTTON_Y":             "[1:2 05]",
        "BUTTON_STICKL":        "[1:2 06]",
        "BUTTON_DLEFT":         "[1:2 08]",
        "BUTTON_DDOWN":         "[1:2 09]",
        "BUTTON_DRIGHT":        "[1:2 0A]",
        "BUTTON_DUP":           "[1:2 0B]",
        "BUTTON_L":             "[1:2 0C]",
        "BUTTON_R":             "[1:2 0D]",
        "BUTTON_PLUS":          "[1:2 0E]",
        "BUTTON_MINUS":         "[1:2 0F]",

        "PLAYER_NAME":          "[1:3]",

        "END":                  "[1:4]",
        "BREAK":                "[1:4][0:4]",

        "WAIT":                 "[1:6]",

        "CHOICE_TOP":           "[1:7][0:4]",
        "CHOICE_MIDDLE":        "[0:4][1:8]",
        "CHOICE_BOTTOM":        "[0:4][1:9]"
    }

    # SYMBOLS = { # 1:1
    #     "ARROW_RIGHT":      "00",
    #     "ARROW_UP":         "01",
    #     "ARROW_LEFT":       "02",
    #     "MARK_X":           "08"
    # }


    def __init__(self, path: Path):
        with open(path, 'rb') as f:
            self.msbt = readMSBT(f.read())


    def getEntry(self, entry_name: str) -> MSBTEntry:
        """Returns an entry by name"""

        return self.msbt.get_entry_by_name(entry_name)


    def getEntries(self) -> tuple[MSBTEntry]:
        """Returns a tuple of all the entries"""

        return self.msbt.entries


    def copyEntry(self, entry_name: str, new_name: str) -> MSBTEntry:
        """Copies an existing entry, adds it under a new name, then returns it"""

        entry = copy.deepcopy(self.msbt.get_entry_by_name(entry_name))
        entry.name = new_name
        self.msbt.add_entry(entry)
        return entry


    def addEntry(self, label: str, message: str) -> None:
        """Adds or edits an entry to the text file. Handles adding the necessary tags based on [COMMAND]"""

        for cmd in self.COMMANDS:
            message = message.replace(f"[{cmd}]", self.COMMANDS[cmd])

        if label in self.msbt._label_map:
            entry = self.msbt.get_entry_by_name(label)
        else:
            entry = copy.deepcopy(self.msbt.entries[0])
            entry.name = label
            self.msbt.add_entry(entry)

        entry.message.text = message


    def write(self, output_path: Path, file_name: str) -> None:
        output_path.mkdir(parents=True, exist_ok=True)
        with open(output_path / file_name, 'wb') as f:
            f.write(writeMSBT(self.msbt))


    def getTextDict(self) -> dict:
        return {e.name: e.message.text for e in self.getEntries()}
