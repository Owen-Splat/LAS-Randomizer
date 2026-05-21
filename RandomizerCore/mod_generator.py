from PySide6 import QtCore
from RandomizerCore.Fixes.Events import seashell_mansion
from RandomizerCore.Paths.randomizer_paths import IS_RUNNING_FROM_SOURCE, RESOURCE_PATH
from RandomizerCore.Tools import (bntx_tools, event_tools)
from RandomizerCore.Randomizers import (data, mad_batter, marin)
from pathlib import Path
from RandomizerCore.Fixes.rooms import RoomFixes
from RandomizerCore.Fixes.datasheets import DatasheetFixes
from RandomizerCore.Fixes.events import EventFixes
from RandomizerCore.Helpers.file_manager import FileManager
from RandomizerCore.Helpers.flag_manager import FlagManager
from RandomizerCore.Helpers.item_info_manager import ItemInfoManager
from RandomizerCore.Helpers.item_get_manager import ItemGetManager
from RandomizerCore.Randomizers.music import MusicRandomizer
from RandomizerCore.Randomizers.chests import ChestRandomizer
from RandomizerCore.Randomizers.dampe import DampeRandomizer
from RandomizerCore.Randomizers.fishing import FishingRandomizer
from RandomizerCore.Randomizers.heart_pieces import HeartPieceRandomizer
from RandomizerCore.Randomizers.instruments import InstrumentRandomizer
from RandomizerCore.Randomizers.small_keys import KeyRandomizer
from RandomizerCore.Randomizers.owls import OwlStatueRandomizer
from RandomizerCore.Randomizers.rupees import BlueRupeeRandomizer
from RandomizerCore.Randomizers.miscellaneous import MiscRandomizer
from RandomizerCore.Randomizers.rapids import RapidsRandomizer
from RandomizerCore.Randomizers.tarin import TarinRandomizer
from RandomizerCore.Randomizers.trade_quest import TradeQuestRandomizer
import re, random, traceback


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
            self.music_randomizer = MusicRandomizer(self)
            if self.thread_active: DatasheetFixes(self)
            if self.thread_active: EventFixes(self)
            if self.thread_active: RoomFixes(self)

            if self.thread_active: ChestRandomizer(self)
            if self.thread_active: self.makeEventContentChanges()
            if self.thread_active: TradeQuestRandomizer(self)

            if self.thread_active: KeyRandomizer(self) # also handles the golden leaves
            if self.thread_active: HeartPieceRandomizer(self)
            if self.thread_active: InstrumentRandomizer(self)
            # if self.thread_active: self.makeShopChanges()

            if self.thread_active: OwlStatueRandomizer(self)

            if self.thread_active: self.makeGeneralARCChanges()

            # if self.thread_active: self.makeItemModelFixes()
            # if self.thread_active: self.makeItemTextBoxes()

            if self.settings["Blue Rupees"] and self.thread_active:
                BlueRupeeRandomizer(self)

            if self.settings["Shuffled Dungeons"] and self.thread_active:
                self.shuffleDungeons()
                self.shuffleDungeonIcons()

            if self.settings["Bad Pets"] and self.thread_active:
                self.changeLevelConfigs()

        except Exception:
            er = traceback.format_exc()
            print(er)
            self.error.emit(er)

        finally: # regardless if there was an error or not, we want to tell the progress window that this thread has finished
            if IS_RUNNING_FROM_SOURCE:
                print(f'total tasks: {self.progress_value}')
            self.is_done.emit()


    def makeEventContentChanges(self):
        """Patch event flow files to change the items given by NPCs and other events"""

        # Run through for every location that needs an event changed.
        # Note that many of these require some extra fixes which will be handled here too.
        if self.thread_active: TarinRandomizer(self)
        if self.thread_active: self.walrusChanges()
        if self.thread_active: self.christineChanges()
        if self.thread_active: self.invisibleZoraChanges()
        if self.thread_active: self.marinChanges()
        if self.thread_active: self.ghostRewardChanges()
        if self.thread_active: self.clothesFairyChanges()
        if self.thread_active: self.goriyaChanges()
        if self.thread_active: self.manboChanges()
        if self.thread_active: self.mamuChanges()
        if self.thread_active: RapidsRandomizer(self)
        if self.thread_active: MiscRandomizer(self)
        if self.thread_active: FishingRandomizer(self)
        if self.thread_active: DampeRandomizer(self)
        if self.thread_active: self.trendyChanges()
        if self.thread_active: self.seashellMansionChanges()
        if self.thread_active: self.madBatterChanges()
        if self.thread_active: self.moldormChanges()
        if self.thread_active: self.genieChanges()
        if self.thread_active: self.slimeEyeChanges()
        if self.thread_active: self.anglerChanges()
        if self.thread_active: self.slimeEelChanges()
        if self.thread_active: self.facadeChanges()
        if self.thread_active: self.eagleChanges()
        if self.thread_active: self.hotheadChanges()
        if self.thread_active: self.lanmolaChanges()
        if self.thread_active: self.armosKnightChanges()
        if self.thread_active: self.masterStalfosChanges()
        if self.thread_active: self.syrupChanges()


    def walrusChanges(self):
        flow = self.file_manager.readFile('Walrus.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('walrus')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event53', 'Event110')
        self.file_manager.writeFile('Walrus.bfevfl', flow)


    def christineChanges(self):
        flow = self.file_manager.readFile('Christine.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('christine-grateful')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event44', 'Event36')
        self.file_manager.writeFile('Christine.bfevfl', flow)


    def invisibleZoraChanges(self):
        flow = self.file_manager.readFile('SecretZora.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('invisible-zora')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event23', 'Event27')
        event_tools.insertEventAfter(flow.flowchart, 'Event32', 'Event23')
        self.file_manager.writeFile('SecretZora.bfevfl', flow)


    def marinChanges(self):
        flow = self.file_manager.readFile('Marin.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('marin')

        if self.settings["Song Cutscenes"]: # skip the cutscene if fast-songs is enabled, and make Link sad about it
            sad_face = event_tools.createActionEvent(flow.flowchart, 'Link', 'SetFacialExpression',
                {'expression': 'sad'}, None)
            flag_set = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
                {'symbol': 'MarinsongGet', 'value': True}, sad_face)
            event_tools.insertEventAfter(flow.flowchart, 'Event92', flag_set)
            self.item_get_manager.get(flow.flowchart, item_key, item_index, sad_face, 'Event666')
        else:
            self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event246', 'Event666')

        marin.makeEventChanges(flow)
        self.file_manager.writeFile('Marin.bfevfl', flow)


    def ghostRewardChanges(self):
        flow = self.file_manager.readFile('Owl.bfevfl')
        new = event_tools.createActionEvent(flow.flowchart, 'Owl', 'Destroy', {})
        item_key, item_index = self.item_info_manager.getItemInfo('ghost-reward')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event34', new)
        self.file_manager.writeFile('Owl.bfevfl', flow)


    def clothesFairyChanges(self):
        flow = self.file_manager.readFile('FairyQueen.bfevfl')

        item_key, item_index = self.item_info_manager.getItemInfo('D0-fairy-2')
        item2 = self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event0', 'Event180')

        item_key, item_index = self.item_info_manager.getItemInfo('D0-fairy-1')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event0', item2)

        event_tools.insertEventAfter(flow.flowchart, 'Event128', 'Event58')

        # make the fairy queen send the player to the proper exit if Shuffle Dungeons is on
        if self.settings["Shuffled Dungeons"]:
            ent_keys = list(self.placements['dungeon-entrances'].keys())
            ent_values = list(self.placements['dungeon-entrances'].values())
            d = data.DUNGEON_ENTRANCES[ent_keys[ent_values.index('color-dungeon')]]
            destin = d[2] + d[3]
            warp_event = event_tools.findEvent(flow.flowchart, 'Event37')
            warp_event.data.params.data['level'] = re.match('(.+)_\\d\\d[A-Z]', destin).group(1)
            warp_event.data.params.data['locator'] = destin

        self.file_manager.writeFile('FairyQueen.bfevfl', flow)


    def goriyaChanges(self):
        flow = self.file_manager.readFile('Goriya.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': "GoriyaItemGetFlag", 'value': True}, 'Event4')

        item_key, item_index = self.item_info_manager.getItemInfo('goriya-trader')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event87', flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': "GoriyaItemGetFlag"}, {0: 'Event7', 1: 'Event15'})
        event_tools.insertEventAfter(flow.flowchart, 'Event24', flag_check)

        self.file_manager.writeFile('Goriya.bfevfl', flow)


    def manboChanges(self):
        flow = self.file_manager.readFile('ManboTamegoro.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': "ManboItemGetFlag", 'value': True}, 'Event13')

        if self.settings["Song Cutscenes"]: # skip the cutscene if fast-songs is enabled
            before_item = 'Event44'
        else:
            before_item = 'Event31'

        item_key, item_index = self.item_info_manager.getItemInfo('manbo')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, before_item, flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': "ManboItemGetFlag"}, {0: 'Event37', 1: 'Event35'})
        event_tools.insertEventAfter(flow.flowchart, 'Event9', flag_check)

        self.file_manager.writeFile('ManboTamegoro.bfevfl', flow)


    def mamuChanges(self):
        flow = self.file_manager.readFile('Mamu.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': "MamuItemGetFlag", 'value': True}, 'Event40')

        if self.settings["Song Cutscenes"]: # skip the cutscene if fast-songs is enabled
            before_item = 'Event55'
        else:
            before_item = 'Event85'

        item_key, item_index = self.item_info_manager.getItemInfo('mamu')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, before_item, flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': "MamuItemGetFlag"}, {0: 'Event14', 1: 'Event98'})
        event_tools.insertEventAfter(flow.flowchart, 'Event10', flag_check)

        self.file_manager.writeFile('Mamu.bfevfl', flow)


    def trendyChanges(self):
        flow = self.file_manager.readFile('GameShopOwner.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('trendy-prize-final')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event112', 'Event239')
        self.file_manager.writeFile('GameShopOwner.bfevfl', flow)


    def seashellMansionChanges(self):
        flow = self.file_manager.readFile('ShellMansionMaster.bfevfl')

        item_key, item_index = self.item_info_manager.getItemInfo('5-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event36').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell10'}

        item_key, item_index = self.item_info_manager.getItemInfo('15-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event10').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell20'}

        item_key, item_index = self.item_info_manager.getItemInfo('30-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event11').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell30'}

        item_key, item_index = self.item_info_manager.getItemInfo('50-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event13').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell50'}

        item_key, item_index = self.item_info_manager.getItemInfo('40-seashell-reward')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event91', 'Event79')

        seashell_mansion.makeEventChanges(flow.flowchart, self.placements)
        self.file_manager.writeFile('ShellMansionMaster.bfevfl', flow)


    def madBatterChanges(self):
        flow = self.file_manager.readFile('MadBatter.bfevfl')

        item_key, item_index = self.item_info_manager.getItemInfo('mad-batter-bay')
        item1 = self.item_get_manager.get(flow.flowchart, item_key, item_index, None, 'Event23')

        item_key, item_index = self.item_info_manager.getItemInfo('mad-batter-woods')
        item2 = self.item_get_manager.get(flow.flowchart, item_key, item_index, None, 'Event23')

        item_key, item_index = self.item_info_manager.getItemInfo('mad-batter-taltal')
        item3 = self.item_get_manager.get(flow.flowchart, item_key, item_index, None, 'Event23')

        mad_batter.writeEvents(flow, item1, item2, item3)

        event_tools.setEventSong(flow.flowchart, 'Event18', self.music_randomizer.songs_dict['BGM_MADBATTER'])
        event_tools.setEventSong(flow.flowchart, 'Event150', self.music_randomizer.songs_dict['BGM_MADBATTER'])

        self.file_manager.writeFile('MadBatter.bfevfl', flow)


    def moldormChanges(self):
        '''Edits Moldorm to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('DeguTail.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D1-moldorm')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event8', 'Event45')

        event_tools.setEventSong(flow.flowchart, 'Event16', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event19', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event65', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event30', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('DeguTail.bfevfl', flow)


    def genieChanges(self):
        '''Edits Genie to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('PotDemonKing.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D2-genie')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event29', 'Event56')

        event_tools.setEventSong(flow.flowchart, 'Event5', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event6', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event53', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event50', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('PotDemonKing.bfevfl', flow)


    def slimeEyeChanges(self):
        '''Edits Slime Eye to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('DeguZol.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D3-slime-eye')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event29', 'Event43')

        event_tools.setEventSong(flow.flowchart, 'Event17', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event36', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event32', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('DeguZol.bfevfl', flow)


    def anglerChanges(self):
        '''Edits Angler Fish to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('Angler.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D4-angler')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event25', 'Event50')

        event_tools.setEventSong(flow.flowchart, 'Event5', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event28', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event29', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event51', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])

        self.file_manager.writeFile('Angler.bfevfl', flow)


    def slimeEelChanges(self):
        '''Edits Slime Eel to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('Hooker.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D5-slime-eel')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event28', 'Event13')

        event_tools.setEventSong(flow.flowchart, 'Event26', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event33', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event49', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event20', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('Hooker.bfevfl', flow)


    def facadeChanges(self):
        '''Edits Facade to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('MatFace.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D6-facade')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event8', 'Event35')

        event_tools.setEventSong(flow.flowchart, 'Event22', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event29', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event78', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event19', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('MatFace.bfevfl', flow)


    def eagleChanges(self):
        '''Edits Evil Eagle to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('Albatoss.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D7-eagle')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event40', 'Event51')

        event_tools.setEventSong(flow.flowchart, 'Event15', self.music_randomizer.songs_dict['BGM_DUNGEON_LV7_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event20', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event66', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])

        self.file_manager.writeFile('Albatoss.bfevfl', flow)


    def hotheadChanges(self):
        '''Edits HotHead to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('DeguFlame.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D8-hothead')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event13', 'Event15')

        event_tools.setEventSong(flow.flowchart, 'Event28', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event40', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event63', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event17', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event70', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('DeguFlame.bfevfl', flow)


    def lanmolaChanges(self):
        '''Edits Lanmola to give the randomized item over dropping the Angler Key'''

        flow = self.file_manager.readFile('Lanmola.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('lanmola')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event34', 'Event9')

        event_tools.setEventSong(flow.flowchart, 'Event2', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event18', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event22', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])

        self.file_manager.writeFile('Lanmola.bfevfl', flow)


    def armosKnightChanges(self):
        '''Edits Armos Knight to open the doors before giving the randomized item'''

        flow = self.file_manager.readFile('DeguArmos.bfevfl')
        event_tools.removeEventAfter(flow.flowchart, 'Event2')
        event_tools.insertEventAfter(flow.flowchart, 'Event2', 'Event8')
        item_key, item_index = self.item_info_manager.getItemInfo('armos-knight')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event47', None)

        event_tools.setEventSong(flow.flowchart, 'Event4', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event23', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])

        self.file_manager.writeFile('DeguArmos.bfevfl', flow)


    def masterStalfosChanges(self):
        '''Edits Master Stalfos to give the randomized item over dropping the Hookshot'''

        flow = self.file_manager.readFile('MasterStalfon.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D5-master-stalfos')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event37', 'Event194')

        event_tools.setEventSong(flow.flowchart, 'Event0', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event1', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event3', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event132', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event157', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event2', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event4', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event10', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event23', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])

        self.file_manager.writeFile('MasterStalfon.bfevfl', flow)


    def syrupChanges(self):
        '''Edits the witch to give the randomized item instead of Magic Powder'''

        flow = self.file_manager.readFile('Syrup.bfevfl')

        # check for mushroom first, if the user has it then give the randomized item
        # if not, check if the user has obtained Magic Powder (GetMagicPowder flag)
        # if so, give a full refill for free
        event_tools.insertEventAfter(flow.flowchart, "talk", "Event43")
        check_event = event_tools.createSwitchEvent(flow.flowchart, "EventFlags", "CheckFlag",
            {"symbol": "GetMagicPowder"},
            {0: "Event44", 1: "Event102"})
        event_tools.setSwitchEventCase(flow.flowchart, "Event43", 0, check_event)

        # give the randomized item when trading in the mushroom
        item_key, item_index = self.item_info_manager.getItemInfo('syrup')
        self.item_get_manager.get(flow.flowchart, item_key, item_index, 'Event93', None)

        # event_tools.setEventSong(flow.flowchart, 'Event56', self.music_randomizer.songs_dict['BGM_SHOP_FAST'])
        # event_tools.setEventSong(flow.flowchart, 'Event13', self.music_randomizer.songs_dict['BGM_SHOP_FAST'])

        self.file_manager.writeFile('Syrup.bfevfl', flow)


    def makeGeneralARCChanges(self):
        """Replaces the Title Screen logo with the Randomizer logo"""

        try:
            # Read the BNTX file from the sarc file and edit the title screen logo to include the randomizer logo
            sarc_data = self.file_manager.readFile('StartUp.arc')
            bntx_tools.createRandomizerTitleScreenArchive(sarc_data)
            self.file_manager.writeFile('StartUp.arc', sarc_data)
        except:
            # regardless of any errors, just consider this task done, the logo is not needed to play
            self.progress_value += 1
            self.progress_update.emit(self.progress_value)


    # def makeShopChanges(self):
    #     """Edits the shop items datasheet as well as event files relating to buying/stealing

    #     NOT FINISHED!!!

    #     This needs ASM to set the GettingFlag of the stolen items"""

    #     if self.thread_active:
    #         sheet = self.file_manager.readFile('ShopItem.gsheet')
    #         shop.makeDatasheetChanges(sheet, self.placements, self.item_defs)
    #         self.file_manager.writeFile('ShopItem.gsheet', sheet)

    #     # ### ToolShopkeeper event - edit events related to manually buying items
    #     # if self.thread_active:
    #     #     flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ToolShopkeeper.bfevfl')
    #     #     shop.makeBuyingEventChanges(flow.flowchart, self.placements, self.item_defs)
    #     #     # event_tools.writeFlow(f'{self.out_dir}/region_common/event/ToolShopkeeper.bfevfl', flow)
    #     #     self.progress_value += 1 # update progress bar
    #     #     self.progress_update.emit(self.progress_value)

    #     # ### PlayerStart event - edit events related to stealing items
    #     # if self.thread_active:
    #     #     # flow = event_tools.readFlow(f'{self.out_dir}/region_common/event/PlayerStart.bfevfl')
    #     #     shop.makeStealingEventChanges(flow.flowchart, self.placements, self.item_defs)
    #     #     event_tools.writeFlow(f'{self.romfs_dir}/region_common/event/ToolShopkeeper.bfevfl', flow)
    #     #     # event_tools.writeFlow(f'{self.out_dir}/region_common/event/PlayerStart.bfevfl', flow)
    #     #     self.progress_value += 1 # udate progress bar
    #     #     self.progress_update.emit(self.progress_value)


# TRENDY GAME STUFF, DO NOT DELETE

    # def makeItemModelFixes(self):
    #     """Adds necessary model files needed for various different fixes"""

    #     if not os.path.exists(f'{self.out_dir}/region_common/actor'):
    #         os.makedirs(f'{self.out_dir}/region_common/actor')

    #     # files = os.listdir(MODELS_PATH)

    #     # for file in files:
    #     #     model = file[:-len(data.MODELS_SUFFIX)] # Switched from Python 3.10 to 3.8, so cant use str.removesuffix lol
    #     #     if model in data.CUSTOM_MODELS:
    #     #         shutil.copy(os.path.join(MODELS_PATH, file), f'{self.out_dir}/region_common/actor/{file}')
    #     #         self.progress_value += 1 # update progress bar
    #     #         self.progress_update.emit(self.progress_value)

    #     if self.thread_active:
    #         crane_prizes.makePrizeModels(self.rom_path, self.out_dir, self.placements, self.item_defs)
    #         self.progress_value += 1 # update progress bar
    #         self.progress_update.emit(self.progress_value)  


    def shuffleDungeons(self):
        """Shuffles the entrances of each dungeon"""

        ent_keys = list(self.placements['dungeon-entrances'].keys())
        ent_values = list(self.placements['dungeon-entrances'].values())

        for k,v in data.DUNGEON_ENTRANCES.items():

            ######################################################################## - dungeon in
            if not self.thread_active:
                break

            room_data = self.file_manager.readFile(f'{v[2]}.leb')

            d = data.DUNGEON_ENTRANCES[self.placements['dungeon-entrances'][k]]
            destin = d[0] + d[1]
            room_data.setLoadingZoneTarget(destin, v[4])

            self.file_manager.writeFile(f'{v[2]}.leb', room_data)

            ######################################################################## - dungeon out
            if not self.thread_active:
                break

            room_data = self.file_manager.readFile(f'{v[0]}.leb')

            d = data.DUNGEON_ENTRANCES[ent_keys[ent_values.index(k)]]
            destin = d[2] + d[3]
            room_data.setLoadingZoneTarget(destin, 0)

            self.file_manager.writeFile(f'{v[0]}.leb', room_data)


    def shuffleDungeonIcons(self):
        """Shuffle the dungeon icons so that players can use the in-game map to track dungeon entrances"""

        icon_keys = list(data.DUNGEON_MAP_ICONS.keys())
        icon_values = list(data.DUNGEON_MAP_ICONS.values())
        maps = [i[0] for i in icon_values]
        sheet = self.file_manager.readFile('UiFieldMapIcons.gsheet')
        for icon in sheet['values']:
            if not self.thread_active:
                break

            if icon['mNameLabel'] in maps:
                k = icon_keys[maps.index(icon['mNameLabel'])]
                new_k = self.placements['dungeon-entrances'][k]
                icon['mNameLabel'] = data.DUNGEON_MAP_ICONS[new_k][0]
                icon['mFirstShowFlagName'] = data.DUNGEON_MAP_ICONS[new_k][1]

        self.file_manager.writeFile('UiFieldMapIcons.gsheet', sheet)


    def changeLevelConfigs(self):
        """Edits the config of the lvb files for dungeons to allow companions"""

        levels_path = self.rom_path / "region_common" / "level"

        # allow companions inside every dungeon
        # exception being the Egg since companions can collide with Nightmare and cause a softlock
        folders = [f.name for f in levels_path.iterdir() if f.name.startswith("Lv") and not f.name.startswith("Lv09")]

        for folder in folders:
            if not self.thread_active:
                break

            level = self.file_manager.readFile(f'{folder}.lvb')
            level.config.allow_companions = True
            self.file_manager.writeFile(f'{folder}.lvb', level)
