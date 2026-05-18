from RandomizerCore.Fixes.Datasheets.conditions import ConditionsDatasheetFixes
from RandomizerCore.Fixes.Datasheets.crane_game import CraneGameDatasheetFixes
from RandomizerCore.Fixes.Datasheets.item_drop import ItemDropDatasheetFixes
from RandomizerCore.Fixes.Datasheets.items import ItemsDatasheetFixes
from RandomizerCore.Fixes.Datasheets.npc import NpcDatasheetFixes
from RandomizerCore.Fixes.Datasheets.fishing import FishingDatasheetFixes


class DatasheetFixes:
    def __init__(self, mod_generator):
        self.parent = mod_generator
        self.makeGeneralDatasheetChanges()


    def makeGeneralDatasheetChanges(self):
        """Make changes to some datasheets that are general in nature and not tied to specific item placements"""

        if self.parent.thread_active: NpcDatasheetFixes(self.parent)
        if self.parent.thread_active: ItemDropDatasheetFixes(self.parent)
        if self.parent.thread_active: ItemsDatasheetFixes(self.parent)
        if self.parent.thread_active: ConditionsDatasheetFixes(self.parent)
        if self.parent.thread_active: CraneGameDatasheetFixes(self.parent)
        if self.parent.thread_active: FishingDatasheetFixes(self.parent)
