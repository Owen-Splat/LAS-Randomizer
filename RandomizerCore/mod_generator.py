from PySide6 import QtCore
from RandomizerCore.Paths.randomizer_paths import IS_RUNNING_FROM_SOURCE, RESOURCE_PATH
from RandomizerCore.Tools import (bntx_tools, event_tools, leb, lvb, oead_tools)
from RandomizerCore.Randomizers import (conditions, crane_prizes, dampe, data, fishing, flags,
item_drops, item_get, mad_batter, marin, miscellaneous, npcs, player_start, rapids,
seashell_mansion, shop, tarin, trade_quest, tunic_swap)
from pathlib import Path
from RandomizerCore.Fixes.rooms import RoomFixes
from RandomizerCore.Helpers.file_manager import FileManager
from RandomizerCore.Helpers.item_info_manager import ItemInfoManager
from RandomizerCore.Randomizers.music import MusicRandomizer
from RandomizerCore.Randomizers.chests import ChestRandomizer
from RandomizerCore.Randomizers.heart_pieces import HeartPieceRandomizer
from RandomizerCore.Randomizers.instruments import InstrumentRandomizer
from RandomizerCore.Randomizers.small_keys import KeyRandomizer
from RandomizerCore.Randomizers.owls import OwlStatueRandomizer
from RandomizerCore.Randomizers.rupees import BlueRupeeRandomizer
import copy, re, random, shutil, traceback


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

        self.file_manager = FileManager(self)
        self.item_info_manager = ItemInfoManager(self)
        self.trap_models = {} # temp until item info manager is done
        self.dungeon_trap_models = {} # temp until item info manager is done

        self.global_flags = {}

        self.progress_value = 0
        self.thread_active = True


    # STOP THREAD
    def stop(self):
        self.thread_active = False


    # automatically called when this thread is started
    def run(self):
        try:
            self.music_randomizer = MusicRandomizer(self)
            if self.thread_active: self.makeGeneralDatasheetChanges()
            if self.thread_active: self.makeGeneralEventChanges()
            if self.thread_active: RoomFixes(self)

            if self.thread_active: ChestRandomizer(self)
            if self.thread_active: self.makeEventContentChanges()
            if self.thread_active: self.makeTradeQuestChanges()

            if self.thread_active: KeyRandomizer(self) # also handles the golden leaves
            if self.thread_active: HeartPieceRandomizer(self)
            if self.thread_active: InstrumentRandomizer(self)
            # if self.thread_active: self.makeShopChanges()

            if self.thread_active: OwlStatueRandomizer(self)
            if self.thread_active: self.makeTelephoneChanges()

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
        if self.thread_active: self.tarinChanges()
        if self.thread_active: self.sinkingSwordChanges()
        if self.thread_active: self.walrusChanges()
        if self.thread_active: self.christineChanges()
        if self.thread_active: self.invisibleZoraChanges()
        if self.thread_active: self.marinChanges()
        if self.thread_active: self.ghostRewardChanges()
        if self.thread_active: self.clothesFairyChanges()
        if self.thread_active: self.goriyaChanges()
        if self.thread_active: self.manboChanges()
        if self.thread_active: self.mamuChanges()
        if self.thread_active: self.rapidsChanges()
        if self.thread_active: self.fishingChanges()
        if self.thread_active: self.trendyChanges()
        if self.thread_active: self.seashellMansionChanges()
        if self.thread_active: self.madBatterChanges()
        if self.thread_active: self.dampeChanges()
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


    def tarinChanges(self):
        flow = self.file_manager.readFile('Tarin.bfevfl')
        tarin.makeEventChanges(flow.flowchart, self.placements, self.settings, self.item_defs)
        self.file_manager.writeFile('Tarin.bfevfl', flow)


    def sinkingSwordChanges(self):
        flow = self.file_manager.readFile('SinkingSword.bfevfl')

        # Beach
        room_data = self.file_manager.readFile('Field_16C.leb')
        music_shuffled = self.settings["Music"] == "Shuffled" # remove some music that would get cut off
        item_key, item_index, model_path, model_name = self.item_info_manager.getItemInfoWithModel('washed-up', self.trap_models)
        miscellaneous.changeSunkenSword(flow.flowchart, item_key, item_index, model_path, model_name, room_data, music_shuffled)
        self.file_manager.writeFile('Field_16C.leb', room_data)

        # Rooster Cave (bird key)
        room_data = self.file_manager.readFile('EagleKeyCave_01A.leb')
        item_key, item_index, model_path, model_name = self.item_info_manager.getItemInfoWithModel('taltal-rooster-cave', self.trap_models)
        miscellaneous.changeBirdKey(flow.flowchart, item_key, item_index, model_path, model_name, room_data)
        self.file_manager.writeFile('EagleKeyCave_01A.leb', room_data)

        # Dream Shrine (ocarina)
        room_data = self.file_manager.readFile('DreamShrine_01A.leb')
        item_key, item_index, model_path, model_name = self.item_info_manager.getItemInfoWithModel('dream-shrine-left', self.trap_models)
        miscellaneous.changeOcarina(flow.flowchart, item_key, item_index, model_path, model_name, room_data)
        self.file_manager.writeFile('DreamShrine_01A.leb', room_data)

        # Woods (mushroom)
        room_data = self.file_manager.readFile('Field_06A.leb')
        item_key, item_index, model_path, model_name = self.item_info_manager.getItemInfoWithModel('woods-loose', self.trap_models)
        miscellaneous.changeMushroom(flow.flowchart, item_key, item_index, model_path, model_name, room_data)
        self.file_manager.writeFile('Field_06A.leb', room_data)

        # Mermaid Cave (lens)
        room_data = self.file_manager.readFile('MermaidStatue_01A.leb')
        item_key, item_index, model_path, model_name = self.item_info_manager.getItemInfoWithModel('mermaid-cave', self.trap_models)
        miscellaneous.changeLens(flow.flowchart, item_key, item_index, model_path, model_name, room_data)
        self.file_manager.writeFile('MermaidStatue_01A.leb', room_data)

        # Done!
        self.file_manager.writeFile('SinkingSword.bfevfl', flow)


    def walrusChanges(self):
        flow = self.file_manager.readFile('Walrus.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('walrus')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event53', 'Event110')
        self.file_manager.writeFile('Walrus.bfevfl', flow)


    def christineChanges(self):
        flow = self.file_manager.readFile('Christine.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('christine-grateful')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event44', 'Event36')
        self.file_manager.writeFile('Christine.bfevfl', flow)


    def invisibleZoraChanges(self):
        flow = self.file_manager.readFile('SecretZora.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('invisible-zora')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event23', 'Event27')
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
            item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, sad_face, 'Event666')
        else:
            item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event246', 'Event666')

        marin.makeEventChanges(flow)
        self.file_manager.writeFile('Marin.bfevfl', flow)


    def ghostRewardChanges(self):
        flow = self.file_manager.readFile('Owl.bfevfl')
        new = event_tools.createActionEvent(flow.flowchart, 'Owl', 'Destroy', {})
        item_key, item_index = self.item_info_manager.getItemInfo('ghost-reward')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event34', new)
        self.file_manager.writeFile('Owl.bfevfl', flow)


    def clothesFairyChanges(self):
        flow = self.file_manager.readFile('FairyQueen.bfevfl')

        item_key, item_index = self.item_info_manager.getItemInfo('D0-fairy-2')
        item2 = item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event0', 'Event180')

        item_key, item_index = self.item_info_manager.getItemInfo('D0-fairy-1')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event0', item2)

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
            {'symbol': data.GORIYA_FLAG, 'value': True}, 'Event4')

        item_key, item_index = self.item_info_manager.getItemInfo('goriya-trader')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event87', flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': data.GORIYA_FLAG}, {0: 'Event7', 1: 'Event15'})
        event_tools.insertEventAfter(flow.flowchart, 'Event24', flag_check)

        self.file_manager.writeFile('Goriya.bfevfl', flow)


    def manboChanges(self):
        flow = self.file_manager.readFile('ManboTamegoro.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': data.MANBO_FLAG, 'value': True}, 'Event13')

        if self.settings["Song Cutscenes"]: # skip the cutscene if fast-songs is enabled
            before_item = 'Event44'
        else:
            before_item = 'Event31'

        item_key, item_index = self.item_info_manager.getItemInfo('manbo')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, before_item, flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.MANBO_FLAG}, {0: 'Event37', 1: 'Event35'})
        event_tools.insertEventAfter(flow.flowchart, 'Event9', flag_check)

        self.file_manager.writeFile('ManboTamegoro.bfevfl', flow)


    def mamuChanges(self):
        flow = self.file_manager.readFile('Mamu.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': data.MAMU_FLAG, 'value': True}, 'Event40')

        if self.settings["Song Cutscenes"]: # skip the cutscene if fast-songs is enabled
            before_item = 'Event55'
        else:
            before_item = 'Event85'

        item_key, item_index = self.item_info_manager.getItemInfo('mamu')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, before_item, flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.MAMU_FLAG}, {0: 'Event14', 1: 'Event98'})
        event_tools.insertEventAfter(flow.flowchart, 'Event10', flag_check)

        self.file_manager.writeFile('Mamu.bfevfl', flow)


    def rapidsChanges(self):
        flow = self.file_manager.readFile('RaftShopMan.bfevfl')
        rapids.makePrizesStack(flow.flowchart, self.placements, self.item_defs)

        # removed rapids BGM because of it being broken in music rando, so remove the StopBGM events for it
        if self.settings["Music"] == "Shuffled":
            event_tools.insertEventAfter(flow.flowchart, 'timeAttackGoal', 'Event27')
            event_tools.insertEventAfter(flow.flowchart, 'normalGoal', 'Event20')

        self.file_manager.writeFile('RaftShopMan.bfevfl', flow)


    def fishingChanges(self):
        flow = self.file_manager.readFile('Fisherman.bfevfl')
        fishing.makeEventChanges(flow.flowchart, self.placements, self.item_defs)
        fishing.fixFishingBottle(flow.flowchart)
        self.file_manager.writeFile('Fisherman.bfevfl', flow)


    def trendyChanges(self):
        flow = self.file_manager.readFile('GameShopOwner.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('trendy-prize-final')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event112', 'Event239')
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
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event91', 'Event79')

        seashell_mansion.makeEventChanges(flow.flowchart, self.placements)
        self.file_manager.writeFile('ShellMansionMaster.bfevfl', flow)


    def madBatterChanges(self):
        flow = self.file_manager.readFile('MadBatter.bfevfl')

        item_key, item_index = self.item_info_manager.getItemInfo('mad-batter-bay')
        item1 = item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, None, 'Event23')

        item_key, item_index = self.item_info_manager.getItemInfo('mad-batter-woods')
        item2 = item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, None, 'Event23')

        item_key, item_index = self.item_info_manager.getItemInfo('mad-batter-taltal')
        item3 = item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, None, 'Event23')

        mad_batter.writeEvents(flow, item1, item2, item3)

        event_tools.setEventSong(flow.flowchart, 'Event18', self.music_randomizer.songs_dict['BGM_MADBATTER'])
        event_tools.setEventSong(flow.flowchart, 'Event150', self.music_randomizer.songs_dict['BGM_MADBATTER'])

        self.file_manager.writeFile('MadBatter.bfevfl', flow)


    def dampeChanges(self):
        if self.thread_active:
            sheet = self.file_manager.readFile('MapPieceClearReward.gsheet')
            dampe.makeDatasheetChanges(sheet, 3, 'Dampe1')
            dampe.makeDatasheetChanges(sheet, 7, 'Dampe2')
            dampe.makeDatasheetChanges(sheet, 12, 'DampeFinal')
            self.file_manager.writeFile('MapPieceClearReward.gsheet', sheet)

        if self.thread_active:
            sheet = self.file_manager.readFile('MapPieceTheme.gsheet')
            dampe.makeDatasheetChanges(sheet, 3, 'DampeHeart')
            dampe.makeDatasheetChanges(sheet, 9, 'DampeBottle')
            self.file_manager.writeFile('MapPieceTheme.gsheet', sheet)

        if self.thread_active:
            flow = self.file_manager.readFile('Danpei.bfevfl')
            dampe.makeEventChanges(flow.flowchart, self.item_defs, self.placements)
            self.file_manager.writeFile('Danpei.bfevfl', flow)


    def moldormChanges(self):
        '''Edits Moldorm to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('DeguTail.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D1-moldorm')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event8', 'Event45')

        event_tools.setEventSong(flow.flowchart, 'Event16', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event19', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event65', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event30', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('DeguTail.bfevfl', flow)


    def genieChanges(self):
        '''Edits Genie to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('PotDemonKing.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D2-genie')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event29', 'Event56')

        event_tools.setEventSong(flow.flowchart, 'Event5', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event6', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event53', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event50', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('PotDemonKing.bfevfl', flow)


    def slimeEyeChanges(self):
        '''Edits Slime Eye to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('DeguZol.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D3-slime-eye')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event29', 'Event43')

        event_tools.setEventSong(flow.flowchart, 'Event17', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event36', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event32', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('DeguZol.bfevfl', flow)


    def anglerChanges(self):
        '''Edits Angler Fish to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('Angler.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D4-angler')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event25', 'Event50')

        event_tools.setEventSong(flow.flowchart, 'Event5', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event28', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event29', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event51', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])

        self.file_manager.writeFile('Angler.bfevfl', flow)


    def slimeEelChanges(self):
        '''Edits Slime Eel to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('Hooker.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D5-slime-eel')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event28', 'Event13')

        event_tools.setEventSong(flow.flowchart, 'Event26', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event33', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event49', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event20', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('Hooker.bfevfl', flow)


    def facadeChanges(self):
        '''Edits Facade to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('MatFace.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D6-facade')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event8', 'Event35')

        event_tools.setEventSong(flow.flowchart, 'Event22', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event29', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])
        event_tools.setEventSong(flow.flowchart, 'Event78', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event19', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])

        self.file_manager.writeFile('MatFace.bfevfl', flow)


    def eagleChanges(self):
        '''Edits Evil Eagle to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('Albatoss.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D7-eagle')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event40', 'Event51')

        event_tools.setEventSong(flow.flowchart, 'Event15', self.music_randomizer.songs_dict['BGM_DUNGEON_LV7_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event20', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS'])
        event_tools.setEventSong(flow.flowchart, 'Event66', self.music_randomizer.songs_dict['BGM_PANEL_RESULT'])

        self.file_manager.writeFile('Albatoss.bfevfl', flow)


    def hotheadChanges(self):
        '''Edits HotHead to give the randomized item over spawning the Heart Container'''

        flow = self.file_manager.readFile('DeguFlame.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D8-hothead')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event13', 'Event15')

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
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event34', 'Event9')

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
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event47', None)

        event_tools.setEventSong(flow.flowchart, 'Event4', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        event_tools.setEventSong(flow.flowchart, 'Event23', self.music_randomizer.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])

        self.file_manager.writeFile('DeguArmos.bfevfl', flow)


    def masterStalfosChanges(self):
        '''Edits Master Stalfos to give the randomized item over dropping the Hookshot'''

        flow = self.file_manager.readFile('MasterStalfon.bfevfl')
        item_key, item_index = self.item_info_manager.getItemInfo('D5-master-stalfos')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event37', 'Event194')

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
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event93', None)

        # event_tools.setEventSong(flow.flowchart, 'Event56', self.music_randomizer.songs_dict['BGM_SHOP_FAST'])
        # event_tools.setEventSong(flow.flowchart, 'Event13', self.music_randomizer.songs_dict['BGM_SHOP_FAST'])

        self.file_manager.writeFile('Syrup.bfevfl', flow)


    def makeGeneralEventChanges(self):
        """Make changes to some events that should be in every seed, e.g. setting flags for having watched cutscenes"""

        ### PlayerStart event: Sets a bunch of flags for cutscenes being watched/triggered to prevent them from ever happening.
        ### First check if FirstClear is already set, to not do the work more than once and slightly slow down loading zones.
        if self.thread_active:
            flow = self.file_manager.readFile('PlayerStart.bfevfl')
            player_start.makeStartChanges(flow.flowchart, self.settings)

            # skip over BGM_HOUSE_FIRST when Link wakes up because it overlaps with the shuffled zone BGM
            if self.settings["Music"] == "Shuffled":
                event_tools.insertEventAfter(flow.flowchart, 'Event150', 'Event151')

            self.file_manager.writeFile('PlayerStart.bfevfl', flow)

        ### ShellMansionPresent event: Similar to TreasureBox, must make some items progressive and add custom events for other items.
        if self.thread_active:
            flow = self.file_manager.readFile('ShellMansionPresent.bfevfl')
            seashell_mansion.changeRewards(flow.flowchart)
            self.file_manager.writeFile('ShellMansionPresent.bfevfl', flow)

        ### Item: Add and fix some entry points for the ItemGetSequence
        if self.thread_active:
            flow = self.file_manager.readFile('Item.bfevfl')

            event_tools.addEntryPoint(flow.flowchart, 'MagicPowder_MaxUp')
            event_tools.createActionChain(flow.flowchart, 'MagicPowder_MaxUp', [
                ('Dialog', 'Show', {'message': 'SubEvent:ByebyeMadBatter'})
            ])
            event_tools.addEntryPoint(flow.flowchart, 'Bomb_MaxUp')
            event_tools.createActionChain(flow.flowchart, 'Bomb_MaxUp', [
                ('Dialog', 'Show', {'message': 'SubEvent:ByebyeMadBatter'})
            ])
            event_tools.addEntryPoint(flow.flowchart, 'Arrow_MaxUp')
            event_tools.createActionChain(flow.flowchart, 'Arrow_MaxUp', [
                ('Dialog', 'Show', {'message': 'SubEvent:ByebyeMadBatter'})
            ])

            event_tools.findEntryPoint(flow.flowchart, 'GreenClothes').name = 'ClothesGreen'
            event_tools.findEntryPoint(flow.flowchart, 'RedClothes').name = 'ClothesRed'
            event_tools.findEntryPoint(flow.flowchart, 'BlueClothes').name = 'ClothesBlue'
            event_tools.findEntryPoint(flow.flowchart, 'Necklace').name = 'PinkBra'

            # now we need to add events for Dampe rewards
            event_tools.addEntryPoint(flow.flowchart, 'Dampe1')
            item_key = self.item_defs[self.placements['dampe-page-1']]['item-key']
            if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
                dialog_event = event_tools.createSubFlowEvent(flow.flowchart, '',
                    item_key, {})
                event_tools.insertEventAfter(flow.flowchart, 'Dampe1', dialog_event)

            event_tools.addEntryPoint(flow.flowchart, 'DampeHeart')
            item_key = self.item_defs[self.placements['dampe-heart-challenge']]['item-key']
            if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
                dialog_event = event_tools.createSubFlowEvent(flow.flowchart, '',
                    item_key, {})
                event_tools.insertEventAfter(flow.flowchart, 'DampeHeart', dialog_event)

            event_tools.addEntryPoint(flow.flowchart, 'Dampe2')
            item_key = self.item_defs[self.placements['dampe-page-2']]['item-key']
            if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
                dialog_event = event_tools.createSubFlowEvent(flow.flowchart, '',
                    item_key, {})
                event_tools.insertEventAfter(flow.flowchart, 'Dampe2', dialog_event)

            event_tools.addEntryPoint(flow.flowchart, 'DampeBottle')
            item_key = self.item_defs[self.placements['dampe-bottle-challenge']]['item-key']
            if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
                dialog_event = event_tools.createSubFlowEvent(flow.flowchart, '',
                    item_key, {})
                event_tools.insertEventAfter(flow.flowchart, 'DampeBottle', dialog_event)

            event_tools.addEntryPoint(flow.flowchart, 'DampeFinal')
            item_key = self.item_defs[self.placements['dampe-final']]['item-key']
            if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
                dialog_event = event_tools.createSubFlowEvent(flow.flowchart, '',
                    item_key, {})
                event_tools.insertEventAfter(flow.flowchart, 'DampeFinal', dialog_event)

            self.file_manager.writeFile('Item.bfevfl', flow)

        ### MadamMeowMeow: Change her behaviour to always take back BowWow if you have him, and not do anything based on having the Horn
        if self.thread_active:
            flow = self.file_manager.readFile('MadamMeowMeow.bfevfl')

            # Removes BowWowClear flag being set
            event_tools.insertEventAfter(flow.flowchart, 'Event69', 'Event18')

            # Rearranging her dialogue conditions
            event_tools.insertEventAfter(flow.flowchart, 'Event22', 'Event5')
            event_tools.setSwitchEventCase(flow.flowchart, 'Event5', 0, 'Event0')
            event_tools.setSwitchEventCase(flow.flowchart, 'Event5', 1, 'Event52')
            event_tools.setSwitchEventCase(flow.flowchart, 'Event0', 0, 'Event40')
            event_tools.setSwitchEventCase(flow.flowchart, 'Event0', 1, 'Event21')
            event_tools.setSwitchEventCase(flow.flowchart, 'Event21', 0, 'Event80')
            event_tools.findEvent(flow.flowchart, 'Event21').data.params.data['symbol'] = 'BowWowJoin'
            self.file_manager.writeFile('MadamMeowMeow.bfevfl', flow)

        ### WindFishsEgg: Removes the Owl cutscene after opening the egg
        if self.thread_active:
            flow = self.file_manager.readFile('WindFishsEgg.bfevfl')
            event_tools.insertEventAfter(flow.flowchart, 'Event142', None)
            self.file_manager.writeFile('WindFishsEgg.bfevfl', flow)

        ### SkeletalGuardBlue: Make him sell 20 bombs in addition to the 20 powder
        if self.thread_active:
            flow = self.file_manager.readFile('SkeletalGuardBlue.bfevfl')

            # edit Magic Powder amount from 20 to 40 so that it'll max even with the capacity upgrade
            event_tools.findEvent(flow.flowchart, 'Event19').data.params.data['count'] = 40

            # give 60 Bombs so that it'll max even with the capacity upgrade
            add_bombs = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItem',
                {'itemType': 4, 'count': 60, 'autoEquip': False})

            # check GetMagicPowder flag before buying
            # these guards will no longer be a source for getting your main powder, and cannot sell bombs until the player can buy powder
            if self.settings["Shuffled Powder"]:
                check_powder = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
                    {'symbol': 'GetMagicPowder'}, {0: 'Event54', 1: 'Event46'})
                event_tools.setSwitchEventCase(flow.flowchart, 'Event7', 1, check_powder)

            # check BombsFound flag when buying powder so we can give some additional resources if available
            # these guards are not a source for getting your main bombs
            if self.settings["Shuffled Bombs"]:
                check_bombs = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
                    {'symbol': data.BOMBS_FOUND_FLAG}, {0: None, 1: add_bombs})
                event_tools.insertEventAfter(flow.flowchart, 'Event19', check_bombs)
            else:
                event_tools.insertEventAfter(flow.flowchart, 'Event19', add_bombs)

            self.file_manager.writeFile('SkeletalGuardBlue.bfevfl', flow)

        ### Make Save&Quit after getting a GameOver send you back to Marin's house
        if self.thread_active:
            flow = self.file_manager.readFile('Common.bfevfl')

            event_tools.setSwitchEventCase(flow.flowchart, 'Event64', 1,
                event_tools.createActionEvent(flow.flowchart, 'GameControl', 'RequestLevelJump',
                    {'level': 'Field', 'locator': 'Field_11C', 'offsetX': 0.0, 'offsetZ': 0.0},
                    'Event67'))

            # shuffle Rapids race music
            if self.settings["Music"] == "Shuffled":
                # remove the music for now since it gets cut off due to something with setting the new BGM in the lvb file
                event_tools.insertEventAfter(flow.flowchart, 'Event167', None)
                #
                # event_tools.findEvent(flow.flowchart, 'Event78').data.params.data['label'] = self.songs_dict['BGM_RAFTING_TIMEATTACK']
            self.file_manager.writeFile('Common.bfevfl', flow)

        ### PrizeCommon: Change the figure to look for when the fast-trendy setting is on, and makes Yoshi not replace Lens
        if self.thread_active:
            flow = self.file_manager.readFile('PrizeCommon.bfevfl')
            crane_prizes.makeEventChanges(flow.flowchart, self.settings)
            self.file_manager.writeFile('PrizeCommon.bfevfl', flow)


    def makeGeneralDatasheetChanges(self):
        """Make changes to some datasheets that are general in nature and not tied to specific item placements"""

        if self.thread_active:
            sheet = self.file_manager.readFile('Npc.gsheet')
            for npc in sheet['values']:
                if not self.thread_active:
                    break
                npcs.makeNpcChanges(npc, self.placements, self.settings)

            npcs.makeNewNpcs(sheet, self.placements, self.item_defs)
            self.file_manager.writeFile('Npc.gsheet', sheet)

        if self.thread_active:
            sheet = self.file_manager.readFile('ItemDrop.gsheet')
            item_drops.makeDatasheetChanges(sheet, self.settings)
            self.file_manager.writeFile('ItemDrop.gsheet', sheet)

        if self.thread_active:
            sheet = self.file_manager.readFile('Items.gsheet')

            dummy = None
            for item in sheet['values']:
                if not self.thread_active:
                    break

                if item['symbol'] == 'Flippers': # this custom flag is for water loading zones to use
                    item['gettingFlag'] = 'FlippersFound'

                # Set new npcKeys for items to change how they appear when Link holds it up
                if item['symbol'] == 'SmallKey':
                    item['npcKey'] = 'PatchSmallKey'
                if item['symbol'] == 'Honeycomb':
                    item['npcKey'] = 'PatchHoneycomb'
                if item['symbol'] == 'Stick':
                    item['npcKey'] = 'PatchStick'
                if item['symbol'] == 'YoshiDoll': # ocarina and instruments are ItemYoshiDoll actors
                    item['npcKey'] = 'PatchYoshiDoll'
                    dummy = oead_tools.parseStruct(item) # create copy to use as a base for custom entries

                # songs and tunics are patched to use the model from the npcKey
                # capacity upgrades have the same patch, but we don't need to edit them here
                if item['symbol'] == 'Song_WindFish':
                    item['npcKey'] = 'NpcMarin'
                if item['symbol'] == 'Song_Mambo':
                    item['npcKey'] = 'NpcManboTamegoro'
                if item['symbol'] == 'Song_Soul':
                    item['npcKey'] = 'NpcMamu'

                # set the tunic npcKeys to empty strings so that nothing gets held up
                if item['symbol'] == 'ClothesGreen':
                    item['npcKey'] = ''
                if item['symbol'] == 'ClothesRed':
                    item['npcKey'] = ''
                if item['symbol'] == 'ClothesBlue':
                    item['npcKey'] = ''

            if dummy is None:
                raise KeyError('ItemYoshiDoll was not found in Items.gsheet')

            # create new entries for Dampe, which we will use to set the gettingFlag
            # can likely use this same method for trendy and shop in the future
            dummy['symbol'] = 'Dampe1'
            dummy['itemID'] = 63
            dummy['gettingFlag'] = 'Dampe1'
            dummy['npcKey'] = self.item_defs[self.placements['dampe-page-1']]['npc-key']
            sheet['values'].append(oead_tools.dictToStruct(dummy))
            dummy['symbol'] = 'DampeHeart'
            dummy['itemID'] = 64
            dummy['gettingFlag'] = 'DampeHeart'
            dummy['npcKey'] = self.item_defs[self.placements['dampe-heart-challenge']]['npc-key']
            sheet['values'].append(oead_tools.dictToStruct(dummy))
            dummy['symbol'] = 'Dampe2'
            dummy['itemID'] = 65
            dummy['gettingFlag'] = 'Dampe2'
            dummy['npcKey'] = self.item_defs[self.placements['dampe-page-2']]['npc-key']
            sheet['values'].append(oead_tools.dictToStruct(dummy))
            dummy['symbol'] = 'DampeBottle'
            dummy['itemID'] = 66
            dummy['gettingFlag'] = 'DampeBottle'
            dummy['npcKey'] = self.item_defs[self.placements['dampe-bottle-challenge']]['npc-key']
            sheet['values'].append(oead_tools.dictToStruct(dummy))
            dummy['symbol'] = 'DampeFinal'
            dummy['itemID'] = 67
            dummy['gettingFlag'] = 'DampeFinal'
            dummy['npcKey'] = self.item_defs[self.placements['dampe-final']]['npc-key']
            sheet['values'].append(oead_tools.dictToStruct(dummy))

            dummy['symbol'] = 'ShopShovel'
            dummy['itemID'] = 68
            dummy['gettingFlag'] = ''
            sheet['values'].append(oead_tools.dictToStruct(dummy))
            dummy['symbol'] = 'ShopBow'
            dummy['itemID'] = 69
            # dummy['gettingFlag'] = 'ShopBowSteal'
            sheet['values'].append(oead_tools.dictToStruct(dummy))
            dummy['symbol'] = 'ShopHeart'
            dummy['itemID'] = 70
            # dummy['gettingFlag'] = 'ShopHeartSteal'
            sheet['values'].append(oead_tools.dictToStruct(dummy))

            # seashell mansion presents need traps to be items entries each with a unique ID, otherwise gives a GreenRupee
            # even though IDs 128+ cause a crash when they get added to the inventory, traps never actually get added
            # instead of just passing the itemKey to the present event, it checks the ID and passes the first itemKey with that ID
            # so if all the traps had the same ID, every trap would act as the first one (ZapTrap)
            if self.settings["Traps"] != "None":
                dummy['symbol'] = 'ZapTrap'
                dummy['itemID'] = 127
                # dummy['gettingFlag'] = ''
                dummy['npcKey'] = 'NpcToolShopkeeper'
                sheet['values'].append(oead_tools.dictToStruct(dummy))
                dummy['symbol'] = 'DrownTrap'
                dummy['itemID'] = 128
                sheet['values'].append(oead_tools.dictToStruct(dummy))
                dummy['symbol'] = 'SquishTrap'
                dummy['itemID'] = 129
                sheet['values'].append(oead_tools.dictToStruct(dummy))
                dummy['symbol'] = 'DeathballTrap'
                dummy['itemID'] = 130
                sheet['values'].append(oead_tools.dictToStruct(dummy))
                dummy['symbol'] = 'QuakeTrap'
                dummy['itemID'] = 131
                sheet['values'].append(oead_tools.dictToStruct(dummy))
                # dummy['symbol'] = 'HydroTrap'
                # dummy['itemID'] = 132
                # sheet['values'].append(oead_tools.dictToStruct(dummy))

            dummy['symbol'] = 'FishNecklace'
            dummy['itemID'] = 200
            dummy['npcKey'] = 'FishNecklace'
            sheet['values'].append(oead_tools.dictToStruct(dummy))
            dummy['symbol'] = 'SyrupPowder'
            dummy['itemID'] = 201
            dummy['npcKey'] = 'SyrupPowder'
            sheet['values'].append(oead_tools.dictToStruct(dummy))
            dummy['symbol'] = 'WalrusShell'
            dummy['itemID'] = 202
            dummy['npcKey'] = 'WalrusShell'
            sheet['values'].append(oead_tools.dictToStruct(dummy))

            self.file_manager.writeFile('Items.gsheet', sheet)

        if self.thread_active:
            sheet = self.file_manager.readFile('Conditions.gsheet')

            for condition in sheet['values']:
                if not self.thread_active:
                    break
                conditions.editConditions(condition, self.settings)

            conditions.makeConditions(sheet, self.placements)
            self.file_manager.writeFile('Conditions.gsheet', sheet)

        if self.thread_active:
            sheet = self.file_manager.readFile('CranePrize.gsheet')
            crane_prizes.makeDatasheetChanges(sheet, self.settings)
            self.file_manager.writeFile('CranePrize.gsheet', sheet)

        if self.thread_active:
            group1 = self.file_manager.readFile('CranePrizeFeaturedPrizeGroup1.gsheet')
            # group2 = self.file_manager.readFile('CranePrizeFeaturedPrizeGroup2.gsheet')
            crane_prizes.changePrizeGroups(group1)
            self.file_manager.writeFile('CranePrizeFeaturedPrizeGroup1.gsheet', group1)
            # self.file_manager.writeFile('CranePrizeFeaturedPrizeGroup2.gsheet', group2)

        if self.thread_active:
            sheet = self.file_manager.readFile('GlobalFlags.gsheet')
            sheet, self.global_flags = flags.makeFlags(sheet)
            self.file_manager.writeFile('GlobalFlags.gsheet', sheet)

        if self.settings["Fast Fishing"] and self.thread_active:
            sheet = self.file_manager.readFile('FishingFish.gsheet')

            for fish in sheet['values']:
                if not self.thread_active:
                    break

                if len(fish['mOpenItem']) > 0:
                    fish['mOpenItem'] = 'ClothesGreen'

            self.file_manager.writeFile('FishingFish.gsheet', sheet)


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


    def makeTelephoneChanges(self):
        """Edits the telephone event file to allow the player to freely swap tunics

        [Not Implemented] Also adds rooster and bowwow to be able to get them back if companion shuffle is on"""

        flow = self.file_manager.readFile('Telephone.bfevfl')
        tunic_swap.writeSwapEvents(flow.flowchart)
        self.file_manager.writeFile('Telephone.bfevfl', flow)

        # if self.settings['shuffle-companions']:
        #     telephones = [
        #         'TelephoneBox01_Ukuku1',
        #         'TelephoneBox02_Mebe',
        #         'TelephoneBox03_Kanalet',
        #         'TelephoneBox04_AnimalVillage',
        #         'TelephoneBox05_TurtleRock',
        #         'TelephoneBox06_Goponga',
        #         'TelephoneBox07_Ukuku2',
        #         'TelephoneBox08_Martha'
        #     ]

        #     for e, tel in enumerate(telephones):
        #         if not os.path.exists(f'{self.out_dir}/region_common/level/{tel}'):
        #             os.makedirs(f'{self.out_dir}/region_common/level/{tel}')

        #         with open(f'{self.rom_path}/region_common/level/{tel}/{tel}_01A.leb', 'rb') as file:
        #             room_data = leb.Room(file.read())

        #         room_data.addTelephoneRooster(e)

        #         if self.thread_active:
        #             with open(f'{self.out_dir}/region_common/level/{tel}/{tel}_01A.leb', 'wb') as file:
        #                 file.write(room_data.repack())
        #                 self.progress_value += 1 # update progress bar
        #                 self.progress_update.emit(self.progress_value)

        #     flow = event_tools.readFlow(f'{self.out_dir}/region_common/event/SinkingSword.bfevfl')

        #     event_tools.addEntryPoint(flow.flowchart, 'GiveBackRooster')

        #     rooster_fork = event_tools.createForkEvent(flow.flowchart, None, [
        #         event_tools.createActionChain(flow.flowchart, None, [
        #             ('Dialog', 'Show', {'message': 'Scenario:GetFlyingCocco'}),
        #             ('FlyingCucco[FlyCocco]', 'StopTailorOtherChannel', {'channel': 'FlyingCucco_get', 'index': 0}),
        #             ('FlyingCucco[FlyCocco]', 'PlayAnimation', {'blendTime': 0.0, 'name': 'ev_glad_ed'}),
        #             ('FlyingCucco[FlyCocco]', 'CancelCarried', {}),
        #             ('FlyingCucco[FlyCocco]', 'Join', {}),
        #             # ('Link', 'SetDisablePowerUpEffect', {'effect': False, 'materialAnim': False, 'sound': False}),
        #             ('GameControl', 'RequestAutoSave', {})
        #         ], None),
        #         event_tools.createActionChain(flow.flowchart, None, [
        #             ('Timer', 'Wait', {'time': 3.3})
        #             # ('Audio', 'PlayZoneBGM', {'stopbgm': True})
        #         ], None)
        #     ], None)[0]
        #     rooster_get = event_tools.createActionChain(flow.flowchart, None, [
        #         ('EventFlags', 'SetFlag', {'symbol': data.ROOSTER_FOUND_FLAG, 'value': True}),
        #         ('FlyingCucco[FlyCocco]', 'Activate', {}),
        #         ('FlyingCucco[FlyCocco]', 'PlayAnimation', {'blendTime': 0.0, 'name': 'FlyingCocco_get'}),
        #         ('Link', 'AimCompassPoint', {'direction': 0, 'duration': 0.1, 'withoutTurn': False}),
        #         ('Link', 'PlayAnimationEx', {'time': 0.0, 'blendTime': 0.0, 'name': 'item_get_lp'}),
        #         ('FlyingCucco[FlyCocco]', 'BeCarried', {}),
        #         ('Link', 'LookAtItemGettingPlayer', {'chaseRatio': 0.1, 'distanceOffset': 0.0, 'duration': 0.7}),
        #         ('Audio', 'PlayOneshotSystemSE', {'label': 'SE_PL_ITEM_GET_LIGHT', 'volume': 1.0, 'pitch': 1.0})
        #     ], rooster_fork)
        #     free_previous = event_tools.createActionChain(flow.flowchart, None, [
        #         ('SinkingSword', 'Destroy', {}),
        #         # ('Link', 'LeaveCompanion', {}),
        #         # ('FlyingCucco[companion]', 'Destroy', {}),
        #         ('BowWow[companion]', 'Destroy', {})
        #     ], rooster_get)

        #     event_tools.insertEventAfter(flow.flowchart, 'GiveBackRooster', free_previous)

        #     if self.thread_active:
        #         event_tools.writeFlow(f'{self.out_dir}/region_common/event/SinkingSword.bfevfl', flow)


    def makeShopChanges(self):
        """Edits the shop items datasheet as well as event files relating to buying/stealing

        NOT FINISHED!!!

        This needs ASM to set the GettingFlag of the stolen items"""

        if self.thread_active:
            sheet = self.file_manager.readFile('ShopItem.gsheet')
            shop.makeDatasheetChanges(sheet, self.placements, self.item_defs)
            self.file_manager.writeFile('ShopItem.gsheet', sheet)

        # ### ToolShopkeeper event - edit events related to manually buying items
        # if self.thread_active:
        #     flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ToolShopkeeper.bfevfl')
        #     shop.makeBuyingEventChanges(flow.flowchart, self.placements, self.item_defs)
        #     # event_tools.writeFlow(f'{self.out_dir}/region_common/event/ToolShopkeeper.bfevfl', flow)
        #     self.progress_value += 1 # update progress bar
        #     self.progress_update.emit(self.progress_value)

        # ### PlayerStart event - edit events related to stealing items
        # if self.thread_active:
        #     # flow = event_tools.readFlow(f'{self.out_dir}/region_common/event/PlayerStart.bfevfl')
        #     shop.makeStealingEventChanges(flow.flowchart, self.placements, self.item_defs)
        #     event_tools.writeFlow(f'{self.romfs_dir}/region_common/event/ToolShopkeeper.bfevfl', flow)
        #     # event_tools.writeFlow(f'{self.out_dir}/region_common/event/PlayerStart.bfevfl', flow)
        #     self.progress_value += 1 # udate progress bar
        #     self.progress_update.emit(self.progress_value)


    def makeTradeQuestChanges(self):
        """Edits various event files for the Trade Quest NPCs to give the randomized items"""

        if self.thread_active:
            flow = self.file_manager.readFile('QuadrupletsMother.bfevfl')
            trade_quest.mamashaChanges(flow.flowchart, self.item_info_manager.getItemInfo('mamasha'))
            self.file_manager.writeFile('QuadrupletsMother.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('RibbonBowWow.bfevfl')
            trade_quest.ciaociaoChanges(flow.flowchart, self.item_info_manager.getItemInfo('ciao-ciao'))
            self.file_manager.writeFile('RibbonBowWow.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('Sale.bfevfl')
            trade_quest.saleChanges(flow.flowchart, self.item_info_manager.getItemInfo('sale'))
            self.file_manager.writeFile('Sale.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('Kiki.bfevfl')
            item_key, item_index, model_path, model_name = self.item_info_manager.getItemInfoWithModel('kiki', self.trap_models)
            trade_quest.kikiChanges(flow.flowchart, self.settings, item_key, item_index)
            # # shuffle bridge building music
            # if self.settings['randomize-music']:
            #     event_tools.findEvent(flow.flowchart, 'Event114').data.params.data['label'] = self.songs_dict['BGM_EVENT_MONKEY']
            #     event_tools.addForkEventForks(flow.flowchart, 'Event102', [
            #         event_tools.createActionEvent(flow.flowchart, 'Audio', 'StopBGM',
            #             {'label': self.songs_dict['BGM_EVENT_MONKEY'], 'duration': 0.0})
            #     ])
            self.file_manager.writeFile('Kiki.bfevfl', flow)
            room_data = self.file_manager.readFile('Field_08L.leb')
            kiki_actor = room_data.actors[0]
            stick_actor = room_data.actors[7]
            # move kiki & the stick if open-bridge is on
            if self.settings["Completed Bridge"]:
                kiki_actor.posX += 1.5
                stick_actor.posX += 1.5
                stick_actor.posZ -= 1.5
            # add the model info to the stick actor parameters
            stick_actor.parameters[1] = bytes(model_path, 'utf-8')
            stick_actor.parameters[2] = bytes(model_name, 'utf-8')
            self.file_manager.writeFile('Field_08L.leb', room_data)

        if self.thread_active:
            flow = self.file_manager.readFile('Tarin.bfevfl')
            trade_quest.tarinChanges(flow.flowchart, self.item_info_manager.getItemInfo('tarin-ukuku'))
            # # shuffle bees music
            # if self.settings['randomize-music']:
            #     event_tools.findEvent(flow.flowchart, 'Event113').data.params.data['label'] = self.songs_dict['BGM_EVENT_BEE']
            self.file_manager.writeFile('Tarin.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('ChefBear.bfevfl')
            trade_quest.chefChanges(flow.flowchart, self.item_info_manager.getItemInfo('chef-bear'))
            self.file_manager.writeFile('ChefBear.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('Papahl.bfevfl')
            trade_quest.papahlChanges(flow.flowchart, self.item_info_manager.getItemInfo('papahl'))
            self.file_manager.writeFile('Papahl.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('Christine.bfevfl')
            trade_quest.christineChanges(flow.flowchart, self.item_info_manager.getItemInfo('christine-trade'))
            self.file_manager.writeFile('Christine.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('DrWrite.bfevfl')
            trade_quest.mrWriteChanges(flow.flowchart, self.item_info_manager.getItemInfo('mr-write'))
            self.file_manager.writeFile('DrWrite.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('GrandmaUlrira.bfevfl')
            trade_quest.grandmaYahooChanges(flow.flowchart, self.item_info_manager.getItemInfo('grandma-yahoo'))
            self.file_manager.writeFile('GrandmaUlrira.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('MarthasBayFisherman.bfevfl')
            trade_quest.fishermanChanges(flow.flowchart, self.item_info_manager.getItemInfo('bay-fisherman'))
            self.file_manager.writeFile('MarthasBayFisherman.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('MermaidMartha.bfevfl')
            trade_quest.mermaidChanges(flow.flowchart, self.item_info_manager.getItemInfo('mermaid-martha'))
            self.file_manager.writeFile('MermaidMartha.bfevfl', flow)

        if self.thread_active:
            flow = self.file_manager.readFile('MarthaStatue.bfevfl')
            trade_quest.statueChanges(flow.flowchart)
            self.file_manager.writeFile('MarthaStatue.bfevfl', flow)


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
