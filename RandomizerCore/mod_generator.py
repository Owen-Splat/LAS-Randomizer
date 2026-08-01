from PySide6 import QtCore
from RandomizerCore.Paths.randomizer_paths import IS_RUNNING_FROM_SOURCE, EXL_PATH
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
from RandomizerCore.Randomizers.shop import ShopRandomizer
from RandomizerCore.Randomizers.keysanity import Keysanity
from RandomizerCore.Randomizers.text import TextRandomizer
from pathlib import Path
import configparser, random, shutil, traceback


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

            if self.thread_active and self.settings["Randomize Text"]: TextRandomizer(self)
            if self.thread_active: Keysanity(self)
            if self.thread_active: ShopRandomizer(self)
            if self.thread_active: EntranceRandomizer(self)

            if self.thread_active: self.makeExeFS()
            if self.thread_active: self.makeConfig()

        except Exception:
            er = traceback.format_exc()
            print(er)
            self.error.emit(er)

        finally: # regardless if there was an error or not, we want to tell the progress window that this thread has finished
            if IS_RUNNING_FROM_SOURCE:
                print(f'total tasks: {self.progress_value}')
            self.is_done.emit()


    def makeExeFS(self) -> None:
        """Creates the main.npdm and subsdk9 files that will go in the exefs folder

        Currently just copies them to the output"""

        self.exefs_dir.mkdir(exist_ok=True)
        shutil.copy(EXL_PATH / "main.npdm", self.exefs_dir)
        shutil.copy(EXL_PATH / "subsdk9", self.exefs_dir)
        self.progress_value += 1
        self.progress_update.emit(self.progress_value)


    def makeConfig(self) -> None:
        """Creates a config.ini file that our exlaunch hooks will read"""

        config = configparser.ConfigParser()
        config.remove_section("DEFAULT")

        config.add_section("movement")
        config["movement"] = {
            "full_direction": self.settings["360 Movement"],
            "speed": 1.2 if self.settings["Movement Speed"] else 1.0
        }

        config.add_section("nice_items")
        config["nice_items"] = {
            "bombs": self.settings["Nice Bombs"],
            "hookshot": self.settings["Nice Hookshot"],
            "rod": self.settings["Nice Magic Rod"]
        }

        config.add_section("blur_removal")
        config["blur_removal"] = {
            "enabled": self.settings["Blur Removal"]
        }

        config.add_section("damage")
        config["damage"] = {
            "mode": self.settings["Damage"]
        }

        config.add_section("randomizer")
        config["randomizer"] = {
            "enabled": True,
            "free_book": self.settings["Free Book"],
            "stealing": self.settings["Stealing"],
            "enemies": self.settings["Randomize Enemies"],
            "enemy_sizes": self.settings["Randomize Enemy Sizes"]
        }

        self.config_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config_dir / "config.ini", 'w') as f:
            config.write(f)
        self.progress_value += 1
        self.progress_update.emit(self.progress_value)
