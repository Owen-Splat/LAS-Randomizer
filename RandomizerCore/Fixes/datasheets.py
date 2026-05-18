from RandomizerCore.Fixes.Datasheets.conditions import ConditionsDatasheetFixes
from RandomizerCore.Fixes.Datasheets.crane_game import CraneGameDatasheetFixes
from RandomizerCore.Fixes.Datasheets.item_drop import ItemDropDatasheetFixes
from RandomizerCore.Fixes.Datasheets.items import ItemsDatasheetFixes
from RandomizerCore.Fixes.Datasheets.npc import NpcDatasheetFixes
from RandomizerCore.Fixes.Datasheets.fishing import FishingDatasheetFixes


class DatasheetFixes:
    """Make changes to some datasheets that are general in nature and not tied to specific item placements"""

    def __init__(self, mod_generator):
        if mod_generator.thread_active: NpcDatasheetFixes(mod_generator)
        if mod_generator.thread_active: ItemDropDatasheetFixes(mod_generator)
        if mod_generator.thread_active: ItemsDatasheetFixes(mod_generator)
        if mod_generator.thread_active: ConditionsDatasheetFixes(mod_generator)
        if mod_generator.thread_active: CraneGameDatasheetFixes(mod_generator)
        if mod_generator.thread_active: FishingDatasheetFixes(mod_generator)
