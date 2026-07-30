from RandomizerCore.Tools.text_tools import TextFile
from pathlib import Path
import random

class TextRandomizer:
    """Handles randomizing unimportant text not used by the randomizer

    Some things we want to leave as vanilla even if the randomizer doesn't use it, like location or item names

    Dialogue with multiple choice is left vanilla for now.
    In the future, they will be randomized with other text with the same number of choices.
    This is due to events that fetch the player's choice.
    Normal dialogue gives it garbage data and results in a game crash"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        self.shuffleText()


    def shuffleText(self) -> None:
        # shuffle text in Talker.msbt first, this simply changes who it says is talking
        text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles("Talker.msbt")
        for file in text_files:
            relative_path, msbt = file

            text_dict = msbt.getTextDict()
            keys = list(text_dict.keys())
            values = list(text_dict.values())
            self.parent.cosmetic_rng.shuffle(keys)
            self.parent.cosmetic_rng.shuffle(values)
            for i in range(len(keys)):
                text_dict[keys[i]] = values[i]
            for entry in msbt.getEntries():
                entry.message.text = text_dict[entry.name]

            self.parent.file_manager.writeTextFile(relative_path, "Talker.msbt", msbt)

        # now randomize several messages across different files, excluding location names, item names, and shop text
        hint_text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles("Hint.msbt")
        npc_text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles("Npc.msbt")
        scenario_text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles("Scenario.msbt")
        subevent_text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles("SubEvent.msbt")
        system_text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles("System.msbt")
        telephone_text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles("Telephone.msbt")

        for i in range(len(hint_text_files)):
            text_messages = {}
            text_messages.update(self.getValidTextDict(hint_text_files[i][1]))
            text_messages.update(self.getValidTextDict(npc_text_files[i][1]))
            text_messages.update(self.getValidTextDict(scenario_text_files[i][1]))
            text_messages.update(self.getValidTextDict(subevent_text_files[i][1]))
            text_messages.update(self.getValidTextDict(system_text_files[i][1]))
            text_messages.update(self.getValidTextDict(telephone_text_files[i][1]))

            keys = list(text_messages.keys())
            values = list(text_messages.values())
            self.parent.cosmetic_rng.shuffle(keys)
            self.parent.cosmetic_rng.shuffle(values)
            for i2 in range(len(keys)):
                text_messages[keys[i2]] = values[i2]

            self.assignRandomizedText("Hint.msbt", text_messages, hint_text_files[i])
            self.assignRandomizedText("Npc.msbt", text_messages, npc_text_files[i])
            self.assignRandomizedText("Scenario.msbt", text_messages, scenario_text_files[i])
            self.assignRandomizedText("SubEvent.msbt", text_messages, subevent_text_files[i])
            self.assignRandomizedText("System.msbt", text_messages, system_text_files[i])
            self.assignRandomizedText("Telephone.msbt", text_messages, telephone_text_files[i])


    def assignRandomizedText(self, file_name: str, text_messages: dict, text_file: tuple[Path, TextFile]) -> None:
        """Goes through all the text files and replaces the messages with the new ones"""

        relative_path, msbt = text_file

        for entry in msbt.getEntries():
            if entry.name not in text_messages:
                return

            new_text: str = text_messages[entry.name]

            # make sure the next text has the same tag for input or not
            if entry.message.text.endswith("[1:4]"):
                if not new_text.endswith("[1:4]"):
                    new_text += "[1:4]"
            else:
                if new_text.endswith("[1:4]"):
                    new_text = new_text.removesuffix("[1:4]")

            # we also need to make sure some messages stay on screen longer like post-instrument messages
            if entry.message.text.endswith("[1:6]"):
                if not new_text.endswith("[1:6]"):
                    new_text += "[1:4]"

            entry.message.text = new_text

        self.parent.file_manager.writeTextFile(relative_path, file_name, msbt)


    def getValidTextDict(self, msbt: TextFile) -> dict:
        """Returns a dictionary of all the valid text in the text_files"""

        text_dict = msbt.getTextDict()
        return {k:v for k,v in text_dict.items() if self.checkValidText(k, v)}


    def checkValidText(self, label, text) -> bool:
        """Checks if the message is okay to be randomized"""

        if "Get" in label:
            return False
        if "Buy" in label:
            return False
        if "Shop" in label:
            return False

        # choice tags usually have [0:4] either before or after it
        # idk if order matters, so simply check for the actual choice tag
        if "[1:7]" in text:
            return False

        return True
