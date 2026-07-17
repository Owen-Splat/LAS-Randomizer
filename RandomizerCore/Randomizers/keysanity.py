import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Tools.text_tools import TextFile
from pathlib import Path


class Keysanity:
    "Handles patching text files and the Item eventflow to support keysanity"

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        self.addTextEvents()
        self.createText()


    def addTextEvents(self) -> None:
        """Add events to display text for the dungeon the item goes to"""

        flow = self.parent.file_manager.readFile("Item.bfevfl")

        for i in range(1, 10):
            event_tools.addEntryPoint(flow.flowchart, f"Keysanity{i}")
            event_tools.createActionChain(flow.flowchart, f"Keysanity{i}", [
                ("Dialog", "Show", {"message": f"Place:Keysanity{i}"})
            ])

        self.parent.file_manager.writeFile("Item.bfevfl", flow)


    def createText(self) -> None:
        """Opens the MSBT files and adds entries for displaying the dungeon text

        We can use the existing dungeon name text, but add a tag at the end to wait for user input"""

        text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles("Place.msbt")

        for file in text_files:
            relative_path, msbt = file
            for i in range(1, 9):
                entry = msbt.copyEntry(f"Lv{i}Dungeon_map", f"Keysanity{i}")
                entry.message.text += "[1:4]" # manually add input tag
            entry = msbt.copyEntry("ClothesDungeon_map", "Keysanity9")
            entry.message.text += "[1:4]" # manually add input tag
            self.parent.file_manager.writeTextFile(relative_path, "Place.msbt", msbt)
