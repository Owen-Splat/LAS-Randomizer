from PySide6 import QtCore
from RandomizerCore.Paths.randomizer_paths import IS_RUNNING_FROM_SOURCE
from RandomizerCore.Fixes.title_screen import TitleScreenFixes
from RandomizerCore.Fixes.datasheets import DatasheetFixes
from RandomizerCore.Fixes.events import EventFixes
from RandomizerCore.Fixes.levels import LevelFixes
from RandomizerCore.Fixes.rooms import RoomFixes
from RandomizerCore.Helpers.item_info_manager import ItemInfoManager
from RandomizerCore.Helpers.item_get_manager import ItemGetManager
from RandomizerCore.Helpers.file_manager import FileManager
from RandomizerCore.Helpers.flag_manager import FlagManager
from RandomizerCore.Randomizers.seashell_mansion import SeashellMansionRandomizer
from RandomizerCore.Randomizers.heart_pieces import HeartPieceRandomizer
from RandomizerCore.Randomizers.instruments import InstrumentRandomizer
from RandomizerCore.Randomizers.trade_quest import TradeQuestRandomizer
from RandomizerCore.Randomizers.trendy_game import TrendyGameRandomizer
from RandomizerCore.Randomizers.free_gifts import FreeGiftsRandomizer
from RandomizerCore.Randomizers.boss_drops import BossDropRandomizer
from RandomizerCore.Randomizers.entrances import EntranceRandomizer
from RandomizerCore.Randomizers.miscellaneous import MiscRandomizer
from RandomizerCore.Randomizers.seashells import SeashellRandomizer
from RandomizerCore.Randomizers.rupees import BlueRupeeRandomizer
from RandomizerCore.Randomizers.fishing import FishingRandomizer
from RandomizerCore.Randomizers.owls import OwlStatueRandomizer
from RandomizerCore.Randomizers.small_keys import KeyRandomizer
from RandomizerCore.Randomizers.rapids import RapidsRandomizer
from RandomizerCore.Randomizers.chests import ChestRandomizer
from RandomizerCore.Randomizers.dampe import DampeRandomizer
from RandomizerCore.Randomizers.music import MusicRandomizer
from RandomizerCore.Randomizers.tarin import TarinRandomizer
from RandomizerCore.Randomizers.keysanity import Keysanity
from pathlib import Path
import random, traceback


class ModsProcess(QtCore.QThread):
    progress_update = QtCore.Signal(int)
    is_done = QtCore.Signal()
    error = QtCore.Signal(str)


    def __init__(self, placements: dict, rom_path: Path, out_dir: Path, items: dict, seed: str, randstate: tuple, parent=None):
        QtCore.QThread.__init__(self, parent)

        self.item_defs = items
        self.placements = placements
        self.settings = self.placements.pop('settings')

        self.rom_path = rom_path
        game_dir = out_dir / "atmosphere" / "contents" / "01006BB00C6F0000"
        self.romfs_dir = game_dir / "romfs"
        self.exefs_dir = game_dir / "exefs" # exefs files that exlaunch creates will be copied to here
        self.config_dir = out_dir / "config" / "lasr-exl" # config file on sd card that our custom code reads settings from

        self.rng = random.Random(seed)
        self.rng.setstate(randstate)
        self.cosmetic_rng = random.Random(seed)
        self.cosmetic_rng.setstate(randstate)

        self.progress_value = 0
        self.thread_active = True

        self.file_manager = FileManager(self)
        self.flag_manager = FlagManager(self)
        self.item_info_manager = ItemInfoManager(self)
        self.trap_models = {} # temp until item info manager is done
        self.dungeon_trap_models = {} # temp until item info manager is done
        self.item_get_manager = ItemGetManager(self)


    # STOP THREAD
    def stop(self):
        self.thread_active = False


    # automatically called when this thread is started
    def run(self):
        try:
            # Other things rely on the music so we need to handle it first
            self.music_randomizer = MusicRandomizer(self)

            # Handle general fixes that are done regardless of item placements
            if self.thread_active: DatasheetFixes(self)
            if self.thread_active: EventFixes(self)
            if self.thread_active: LevelFixes(self)
            if self.thread_active: RoomFixes(self)
            if self.thread_active: TitleScreenFixes(self)

            # Run all of our randomization classes
            if self.thread_active: TarinRandomizer(self)
            if self.thread_active: ChestRandomizer(self)
            if self.thread_active: FreeGiftsRandomizer(self)
            if self.thread_active: TradeQuestRandomizer(self)
            if self.thread_active: SeashellRandomizer(self)
            if self.thread_active: HeartPieceRandomizer(self)
            if self.thread_active: MiscRandomizer(self)
            if self.thread_active: SeashellMansionRandomizer(self)
            if self.thread_active: BossDropRandomizer(self)

            if self.thread_active: DampeRandomizer(self)
            if self.thread_active: RapidsRandomizer(self)
            if self.thread_active: FishingRandomizer(self)
            if self.thread_active: TrendyGameRandomizer(self)

            if self.thread_active: KeyRandomizer(self) # also handles the golden leaves
            if self.thread_active: InstrumentRandomizer(self)

            if self.thread_active: OwlStatueRandomizer(self)
            if self.thread_active: BlueRupeeRandomizer(self)

            if self.thread_active: EntranceRandomizer(self)
            if self.thread_active: Keysanity(self)

        except Exception:
            er = traceback.format_exc()
            print(er)
            self.error.emit(er)

        finally: # regardless if there was an error or not, we want to tell the progress window that this thread has finished
            if IS_RUNNING_FROM_SOURCE:
                print(f'total tasks: {self.progress_value}')
            self.is_done.emit()


    # TODO: MOVE THIS TO ITEM GET MANAGER...
    def checkItemNeedsAnimation(self, item) -> bool:
        """Some items skip over the animation for the sake of speeding up gameplay

        Now with keysanity, we don't want to skip over the animation if the item is part of it"""

        match item:
            case "SmallKey":
                return self.settings["Small Keys"] in ("Any Dungeon", "Anywhere")
            case "NightmareKey":
                return self.settings["Nightmare Keys"] in ("Any Dungeon", "Anywhere")
            case "DungeonMap":
                return self.settings["Dungeon Maps"] in ("Any Dungeon", "Anywhere")
            case "Compass":
                return self.settings["Compasses"] in ("Any Dungeon", "Anywhere")
            case "StoneBeak":
                return self.settings["Stone Beaks"] in ("Any Dungeon", "Anywhere")
            case s if s.startswith("Rupee"):
                return False
            case _:
                return True
