import shutil

from PySide6 import QtCore
from RandomizerCore.ASM import assemble
from RandomizerCore.Paths.randomizer_paths import IS_RUNNING_FROM_SOURCE, RESOURCE_PATH

from RandomizerCore.Tools import (bntx_tools, event_tools, leb, lvb, oead_tools)
from RandomizerCore.Randomizers import (chests, conditions, crane_prizes, dampe, data, fishing, flags, golden_leaves,
heart_pieces, instruments, item_drops, item_get, mad_batter, marin, miscellaneous, npcs, owls, player_start, rapids,
seashell_mansion, shop, small_keys, tarin, trade_quest, tunic_swap)

import os
import re
import copy
import random
import traceback



class ModsProcess(QtCore.QThread):
    
    progress_update = QtCore.Signal(int)
    is_done = QtCore.Signal()
    error = QtCore.Signal(str)


    def __init__(self, placements: dict, rom_path: str, out_dir: str, items: dict, seed: str, randstate: tuple, parent=None):
        QtCore.QThread.__init__(self, parent)

        self.placements = placements
        self.settings = self.placements.pop('settings')

        self.rom_path = rom_path
        if self.settings['platform'] == 'console':
            self.romfs_dir = out_dir + '/atmosphere/contents/01006BB00C6F0000/romfs'
            self.exefs_dir = out_dir + '/atmosphere/exefs_patches/las_randomizer'
        else:
            self.romfs_dir = out_dir + '/romfs'
            self.exefs_dir = out_dir + '/exefs'
        
        self.item_defs = items
        self.instruments = (
            'FullMoonCello',
            'ConchHorn',
            'SeaLilysBell',
            'SurfHarp',
            'WindMarimba',
            'CoralTriangle',
            'EveningCalmOrgan',
            'ThunderDrum'
        )

        self.trap_models = data.ITEM_MODELS.copy()
        
        for i in self.placements['starting-items']:
            i = self.item_defs[i]['item-key']
            if i == 'SwordLv1':
                i = 'SinkingSword'
            if i in ['SinkingSword', 'Shield', 'PowerBraceletLv1']:
                if self.placements['starting-items'].count(i) < 2:
                    continue
            if i in self.trap_models:
                del self.trap_models[i]
        
        if not self.settings['shuffle-instruments']:
            for inst in self.instruments:
                if inst in self.trap_models:
                    del self.trap_models[inst]
        
        self.dungeon_trap_models = self.trap_models.copy()
        self.dungeon_trap_models.update({
            'SmallKey': 'ItemSmallKey.bfres',
            'NightmareKey': 'ItemNightmareKey.bfres',
            'StoneBeak': 'ItemStoneBeak.bfres',
            'Compass': 'ItemCompass.bfres',
            'DungeonMap': 'ItemDungeonMap.bfres'
        })
        
        # if self.settings['dungeon-items'] != 'standard':
        #     self.trap_models.update({
        #     'SmallKey': 'ItemSmallKey.bfres',
        #     'NightmareKey': 'ItemNightmareKey.bfres',
        # })
        
        # if self.settings['dungeon-items'] == 'keys+mcb':
        #     self.trap_models.update({
        #     'StoneBeak': 'ItemStoneBeak.bfres',
        #     'Compass': 'ItemCompass.bfres',
        #     'DungeonMap': 'ItemDungeonMap.bfres'
        # })

        self.seed = seed
        random.seed(seed)
        random.setstate(randstate)
        
        self.global_flags = {}
        self.songs_dict = {}
        self.out_files = set()

        self.progress_value = 0
        self.thread_active = True
    
    

    # STOP THREAD
    def stop(self):
        self.thread_active = False
    
    
    
    # automatically called when this thread is started
    def run(self):
        try:
            if self.settings['randomize-music'] and self.thread_active:
                self.randomizeMusic() # map new music at the beginning so that it is the same by seed, regardless of settings
            
            if self.thread_active: self.makeGeneralLEBChanges()
            if self.thread_active: self.makeGeneralDatasheetChanges()
            if self.thread_active: self.makeGeneralEventChanges()
            
            if self.thread_active: self.makeChestContentFixes()
            if self.thread_active: self.makeEventContentChanges()
            if self.thread_active: self.makeTradeQuestChanges()

            if self.thread_active: self.makeSmallKeyChanges() # also handles the golden leaves
            if self.thread_active: self.makeHeartPieceChanges()
            if self.thread_active: self.makeInstrumentChanges()
            # if self.thread_active: self.makeShopChanges()
            
            if self.thread_active: self.makeOwlStatueChanges()
            if self.thread_active: self.makeTelephoneChanges()

            if self.thread_active: self.makeGeneralARCChanges()
            
            # if self.thread_active: self.makeItemModelFixes()
            # if self.thread_active: self.makeItemTextBoxes()
            
            if self.settings['blupsanity'] and self.thread_active:
                self.makeLv10RupeeChanges()

            if self.settings['shuffle-dungeons'] and self.thread_active:
                self.shuffleDungeons()
                self.shuffleDungeonIcons()
            
            if self.settings['bad-pets'] and self.thread_active:
                self.changeLevelConfigs()
            
            if self.settings['randomize-music'] and self.thread_active:
                self.makeMusicChanges()
            
            if (self.settings['randomize-enemies'] or self.settings['randomize-enemy-sizes']) and self.thread_active:
                self.randomizeEnemies()

            if self.settings['open-mabe'] and self.thread_active:
                self.openMabe()
            
            if self.thread_active: self.fixWaterLoadingZones()
            if self.thread_active: self.fixRapidsRespawn()
            
            # current asm does not appear to break anything, can finally include :)
            if self.thread_active: self.makeExefsPatches()
        
        except Exception:
            er = traceback.format_exc()
            print(er)
            self.error.emit(er)
        
        finally: # regardless if there was an error or not, we want to tell the progress window that this thread has finished
            if IS_RUNNING_FROM_SOURCE:
                print(f'total tasks: {self.progress_value}')
            self.is_done.emit()
    


    def makeChestContentFixes(self):
        """Patch LEB files of rooms with chests to update their contents"""

        chest_rooms = {}
        chest_rooms.update(data.CHEST_ROOMS)

        # CAMC Pre-Checks
        if self.settings['chest-aspect'] == 'camc':
            chest_rooms.update(data.PANEL_CHEST_ROOMS)

            # Creating custom textures bfres files from the original one in the RomFS
            bfresOutputFolder = os.path.join(RESOURCE_PATH, 'textures', 'chest', 'bfres')

            bntx_tools.createChestBfresWithCustomTexturesIfMissing(
                f'{self.rom_path}/region_common/actor/ObjTreasureBox.bfres',
                bfresOutputFolder
            )

            # Copying files to the custom RomFS
            actorOutputFolder = f'{self.romfs_dir}/region_common/actor'
            if not os.path.exists(actorOutputFolder):
                os.makedirs(actorOutputFolder)

            files = os.listdir(bfresOutputFolder)

            # Loop through the files and copy them to the destination directory
            for file in files:
                source = os.path.join(bfresOutputFolder, file)
                destination = os.path.join(actorOutputFolder, file)
                shutil.copy(source, destination)


        # CSMC Management (Chest size)
        chest_sizes = copy.deepcopy(data.CHEST_SIZES)

        if self.settings['chest-aspect'] != 'default':
            # if all seashell and trade gift locations are set to junk, set chests that contain them to be small
            if not self.settings['seashells-important']:
                chest_sizes['seashell'] = 0.8
            if not self.settings['trade-important']:
                chest_sizes['trade'] = 0.8
        else:
            for k in chest_sizes:
                chest_sizes[k] = 1.0  # if scaled chest sizes is off, set every value to normal size

        for room in chest_rooms:
            if not self.thread_active:
                break

            room_data = self.readFile(f'{chest_rooms[room]}.leb')

            # Managing panels to set default chest texture for now as I cannot detect chest content (only $PANEL)
            if room.startswith('panel-'):
                for actor in room_data.actors:
                    if actor.name.startswith(b'ObjTreasureBox'):
                        room_data.setChestContent(
                            actor.parameters[1].decode("utf-8"), actor.parameters[2],
                            chest_size=1.0, chest_model=data.CHEST_TEXTURES['default'])
                self.writeFile(f'{data.PANEL_CHEST_ROOMS[room]}.leb', room_data)
                continue

            item_key, item_index = self.getItemInfo(room)
            item_type = self.item_defs[self.placements[room]]['type']

            # Managing CSMC on the fly. TODO Make this cleaner. This should not be there.
            if self.settings['chest-aspect'] == 'csmc':
                if item_key in ('HeartContainer', 'ClothesRed', 'ClothesBlue'):
                    size = chest_sizes['junk']
                elif item_key in ('SmallKey', 'Bomb_MaxUp', 'Arrow_MaxUp', 'MagicPowder_MaxUp'):
                    size = chest_sizes['important']
                else:
                    size = chest_sizes[item_type]
            else:
                size = chest_sizes[item_type]

            try:
                item_chest_type = self.item_defs[self.placements[room]]['chest-type']
            except KeyError:
                item_chest_type = None

            # Changing the texture and size of Stone Beaks if dungeon Owl rewards are enabled
            if item_key == "StoneBeak" and self.settings['owl-dungeon-gifts']:
                item_chest_type = 'default'
                size = chest_sizes['important']

            # TODO Manage PanelDungeonPiece thanks to Dampe settings (need to check how it works)

            # CAMC Management (Chest aspect - Texture management)
            model = data.CHEST_TEXTURES['default'] if self.settings['chest-aspect'] == 'camc' else None
            if self.settings['chest-aspect'] == 'camc' and item_chest_type is not None:
                model = data.CHEST_TEXTURES[item_chest_type]

            if room == 'taltal-5-chest-puzzle':
                for i in range(5):
                    room_data.setChestContent(item_key, item_index, i, size, model)
            else:
                room_data.setChestContent(item_key, item_index, chest_size=size, chest_model=model)
            
            self.writeFile(f'{data.CHEST_ROOMS[room]}.leb', room_data)
            
            # Two special cases in D7 have duplicate rooms, once for pre-collapse and once for post-collapse. So we need to make sure we write the same data to both rooms.
            if room == 'D7-grim-creeper':
                room_data = self.readFile('Lv07EagleTower_06H.leb')
                room_data.setChestContent(item_key, item_index, chest_size=size, chest_model=model)
                self.writeFile('Lv07EagleTower_06H.leb', room_data)
            
            if room == 'D7-3f-horseheads':
                room_data = self.readFile('Lv07EagleTower_05G.leb')
                room_data.setChestContent(item_key, item_index, chest_size=size, chest_model=model)
                self.writeFile('Lv07EagleTower_05G.leb', room_data)



    def makeSmallKeyChanges(self):
        """Patch SmallKey event and LEB files for rooms with small key drops to change them into other items"""

        # Open up the SmallKey event to be ready to edit
        flow = self.readFile('SmallKey.bfevfl')
        if self.settings['fast-keys']:
            small_keys.makeKeysFaster(flow.flowchart)
        # small_keys.writeSunkenKeyEvent(flow.flowchart)

        for room in data.SMALL_KEY_ROOMS:
            if not self.thread_active:
                break

            room_data = self.readFile(f'{data.SMALL_KEY_ROOMS[room]}.leb')

            if room == 'pothole-final':
                item_key, item_index, model_path, model_name = self.getItemInfo(room, self.trap_models)
                act = room_data.actors[42]
                act.type = 0xa9 # small key
                act.posX += 1.5 # move right one tile
                act.posZ -= 1.5 # move up one tile
                act.switches[0] = (1, self.global_flags['PotholeKeySpawn']) # index of PotholeKeySpawn
                act.switches[1] = (1, 363) # index of the getflag, which is now unused0363
            else:
                item_key, item_index, model_path, model_name = self.getItemInfo(room, self.dungeon_trap_models)
                        
            small_keys.writeKeyEvent(flow.flowchart, item_key, item_index, room)
            room_data.setSmallKeyParams(model_path, model_name, room, item_key)
            self.writeFile(f'{data.SMALL_KEY_ROOMS[room]}.leb', room_data)

            if room == 'D4-sunken-item': # special case. need to write the same data in 06A
                room_data = self.readFile('Lv04AnglersTunnel_06A.leb')
                room_data.setSmallKeyParams(model_path, model_name, room, item_key)
                self.writeFile('Lv04AnglersTunnel_06A.leb', room_data)
        
        if self.thread_active:
            self.makeGoldenLeafChanges(flow)
        


    def makeGoldenLeafChanges(self, flow):
        '''Make small key actors spawn for the golden leaf checks'''

        for room in data.GOLDEN_LEAF_ROOMS:
            if not self.thread_active:
                break

            room_data = self.readFile(f'{data.GOLDEN_LEAF_ROOMS[room]}.leb')
            item_key, item_index, model_path, model_name = self.getItemInfo(room, self.trap_models)
            golden_leaves.createRoomKey(room_data, room, self.global_flags)
            small_keys.writeKeyEvent(flow.flowchart, item_key, item_index, room)
            room_data.setSmallKeyParams(model_path, model_name, room, item_key)
            self.writeFile(f'{data.GOLDEN_LEAF_ROOMS[room]}.leb', room_data)
        
        self.writeFile('SmallKey.bfevfl', flow)



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
        flow = self.readFile('Tarin.bfevfl')
        tarin.makeEventChanges(flow.flowchart, self.placements, self.settings, self.item_defs)
        self.writeFile('Tarin.bfevfl', flow)



    def sinkingSwordChanges(self):
        flow = self.readFile('SinkingSword.bfevfl')

        # Beach
        room_data = self.readFile('Field_16C.leb')
        music_shuffled = self.settings['randomize-music'] # remove some music that would get cut off
        item_key, item_index, model_path, model_name = self.getItemInfo('washed-up', self.trap_models)
        miscellaneous.changeSunkenSword(flow.flowchart, item_key, item_index, model_path, model_name, room_data, music_shuffled)
        self.writeFile('Field_16C.leb', room_data)
        
        ########################################################################################################################
        # Rooster Cave (bird key)
        room_data = self.readFile('EagleKeyCave_01A.leb')
        item_key, item_index, model_path, model_name = self.getItemInfo('taltal-rooster-cave', self.trap_models)
        miscellaneous.changeBirdKey(flow.flowchart, item_key, item_index, model_path, model_name, room_data)
        self.writeFile('EagleKeyCave_01A.leb', room_data)
        
        ##########################################################################################################################
        # Dream Shrine (ocarina)
        room_data = self.readFile('DreamShrine_01A.leb')
        item_key, item_index, model_path, model_name = self.getItemInfo('dream-shrine-left', self.trap_models)
        miscellaneous.changeOcarina(flow.flowchart, item_key, item_index, model_path, model_name, room_data)
        self.writeFile('DreamShrine_01A.leb', room_data)
        
        ##########################################################################################################################
        # Woods (mushroom)
        room_data = self.readFile('Field_06A.leb')
        item_key, item_index, model_path, model_name = self.getItemInfo('woods-loose', self.trap_models)
        miscellaneous.changeMushroom(flow.flowchart, item_key, item_index, model_path, model_name, room_data)
        self.writeFile('Field_06A.leb', room_data)
        
        ##########################################################################################################################
        # Mermaid Cave (lens)
        room_data = self.readFile('MermaidStatue_01A.leb')
        item_key, item_index, model_path, model_name = self.getItemInfo('mermaid-cave', self.trap_models)
        miscellaneous.changeLens(flow.flowchart, item_key, item_index, model_path, model_name, room_data)
        self.writeFile('MermaidStatue_01A.leb', room_data)
        
        #########################################################################################################################
        # Done!
        self.writeFile('SinkingSword.bfevfl', flow)



    def walrusChanges(self):
        flow = self.readFile('Walrus.bfevfl')
        item_key, item_index = self.getItemInfo('walrus')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event53', 'Event110')
        self.writeFile('Walrus.bfevfl', flow)



    def christineChanges(self):
        flow = self.readFile('Christine.bfevfl')
        item_key, item_index = self.getItemInfo('christine-grateful')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event44', 'Event36')
        self.writeFile('Christine.bfevfl', flow)



    def invisibleZoraChanges(self):
        flow = self.readFile('SecretZora.bfevfl')
        item_key, item_index = self.getItemInfo('invisible-zora')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event23', 'Event27')
        event_tools.insertEventAfter(flow.flowchart, 'Event32', 'Event23')
        self.writeFile('SecretZora.bfevfl', flow)



    def marinChanges(self):
        flow = self.readFile('Marin.bfevfl')
        item_key, item_index = self.getItemInfo('marin')

        if self.settings['fast-songs']: # skip the cutscene if fast-songs is enabled, and make Link sad about it
            sad_face = event_tools.createActionEvent(flow.flowchart, 'Link', 'SetFacialExpression',
                {'expression': 'sad'}, None)
            flag_set = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
                {'symbol': 'MarinsongGet', 'value': True}, sad_face)
            event_tools.insertEventAfter(flow.flowchart, 'Event92', flag_set)
            item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, sad_face, 'Event666')
        else:
            item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event246', 'Event666')
            
        marin.makeEventChanges(flow)
        self.writeFile('Marin.bfevfl', flow)



    def ghostRewardChanges(self):
        flow = self.readFile('Owl.bfevfl')
        new = event_tools.createActionEvent(flow.flowchart, 'Owl', 'Destroy', {})
        item_key, item_index = self.getItemInfo('ghost-reward')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event34', new)
        self.writeFile('Owl.bfevfl', flow)



    def clothesFairyChanges(self):
        flow = self.readFile('FairyQueen.bfevfl')

        item_key, item_index = self.getItemInfo('D0-fairy-2')
        item2 = item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event0', 'Event180')

        item_key, item_index = self.getItemInfo('D0-fairy-1')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event0', item2)

        event_tools.insertEventAfter(flow.flowchart, 'Event128', 'Event58')

        # make the fairy queen send the player to the proper exit if Shuffle Dungeons is on
        if self.settings['shuffle-dungeons']:
            ent_keys = list(self.placements['dungeon-entrances'].keys())
            ent_values = list(self.placements['dungeon-entrances'].values())
            d = data.DUNGEON_ENTRANCES[ent_keys[ent_values.index('color-dungeon')]]
            destin = d[2] + d[3]
            warp_event = event_tools.findEvent(flow.flowchart, 'Event37')
            warp_event.data.params.data['level'] = re.match('(.+)_\\d\\d[A-Z]', destin).group(1)
            warp_event.data.params.data['locator'] = destin
        
        self.writeFile('FairyQueen.bfevfl', flow)



    def goriyaChanges(self):
        flow = self.readFile('Goriya.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': data.GORIYA_FLAG, 'value': True}, 'Event4')
        
        item_key, item_index = self.getItemInfo('goriya-trader')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event87', flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': data.GORIYA_FLAG}, {0: 'Event7', 1: 'Event15'})
        event_tools.insertEventAfter(flow.flowchart, 'Event24', flag_check)

        self.writeFile('Goriya.bfevfl', flow)



    def manboChanges(self):
        flow = self.readFile('ManboTamegoro.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': data.MANBO_FLAG, 'value': True}, 'Event13')
        
        if self.settings['fast-songs']: # skip the cutscene if fast-songs is enabled
            before_item = 'Event44'
        else:
            before_item = 'Event31'
        
        item_key, item_index = self.getItemInfo('manbo')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, before_item, flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.MANBO_FLAG}, {0: 'Event37', 1: 'Event35'})
        event_tools.insertEventAfter(flow.flowchart, 'Event9', flag_check)

        self.writeFile('ManboTamegoro.bfevfl', flow)



    def mamuChanges(self):
        flow = self.readFile('Mamu.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': data.MAMU_FLAG, 'value': True}, 'Event40')
        
        if self.settings['fast-songs']: # skip the cutscene if fast-songs is enabled
            before_item = 'Event55'
        else:
            before_item = 'Event85'
        
        item_key, item_index = self.getItemInfo('mamu')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, before_item, flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.MAMU_FLAG}, {0: 'Event14', 1: 'Event98'})
        event_tools.insertEventAfter(flow.flowchart, 'Event10', flag_check)

        self.writeFile('Mamu.bfevfl', flow)



    def rapidsChanges(self):
        flow = self.readFile('RaftShopMan.bfevfl')
        rapids.makePrizesStack(flow.flowchart, self.placements, self.item_defs)

        # removed rapids BGM because of it being broken in music rando, so remove the StopBGM events for it
        if self.settings['randomize-music']:
            event_tools.insertEventAfter(flow.flowchart, 'timeAttackGoal', 'Event27')
            event_tools.insertEventAfter(flow.flowchart, 'normalGoal', 'Event20')
        
        self.writeFile('RaftShopMan.bfevfl', flow)



    def fishingChanges(self):
        flow = self.readFile('Fisherman.bfevfl')
        fishing.makeEventChanges(flow.flowchart, self.placements, self.item_defs)
        fishing.fixFishingBottle(flow.flowchart)
        self.writeFile('Fisherman.bfevfl', flow)



    def trendyChanges(self):
        flow = self.readFile('GameShopOwner.bfevfl')
        item_key, item_index = self.getItemInfo('trendy-prize-final')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event112', 'Event239')
        self.writeFile('GameShopOwner.bfevfl', flow)



    def seashellMansionChanges(self):
        flow = self.readFile('ShellMansionMaster.bfevfl')

        item_key, item_index = self.getItemInfo('5-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event36').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell10'}

        item_key, item_index = self.getItemInfo('15-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event10').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell20'}

        item_key, item_index = self.getItemInfo('30-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event11').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell30'}

        item_key, item_index = self.getItemInfo('50-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event13').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell50'}

        item_key, item_index = self.getItemInfo('40-seashell-reward')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event91', 'Event79')

        seashell_mansion.makeEventChanges(flow.flowchart, self.placements)
        self.writeFile('ShellMansionMaster.bfevfl', flow)



    def madBatterChanges(self):
        flow = self.readFile('MadBatter.bfevfl')

        item_key, item_index = self.getItemInfo('mad-batter-bay')
        item1 = item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, None, 'Event23')

        item_key, item_index = self.getItemInfo('mad-batter-woods')
        item2 = item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, None, 'Event23')

        item_key, item_index = self.getItemInfo('mad-batter-taltal')
        item3 = item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, None, 'Event23')

        mad_batter.writeEvents(flow, item1, item2, item3)

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event18', self.songs_dict['BGM_MADBATTER'])
            event_tools.setEventSong(flow.flowchart, 'Event150', self.songs_dict['BGM_MADBATTER'])
        
        self.writeFile('MadBatter.bfevfl', flow)



    def dampeChanges(self):
        if self.thread_active:
            sheet = self.readFile('MapPieceClearReward.gsheet')
            dampe.makeDatasheetChanges(sheet, 3, 'Dampe1')
            dampe.makeDatasheetChanges(sheet, 7, 'Dampe2')
            dampe.makeDatasheetChanges(sheet, 12, 'DampeFinal')
            self.writeFile('MapPieceClearReward.gsheet', sheet)
        
        if self.thread_active:
            sheet = self.readFile('MapPieceTheme.gsheet')
            dampe.makeDatasheetChanges(sheet, 3, 'DampeHeart')
            dampe.makeDatasheetChanges(sheet, 9, 'DampeBottle')
            self.writeFile('MapPieceTheme.gsheet', sheet)
        
        if self.thread_active:
            flow = self.readFile('Danpei.bfevfl')
            dampe.makeEventChanges(flow.flowchart, self.item_defs, self.placements)
            self.writeFile('Danpei.bfevfl', flow)



    def moldormChanges(self):
        '''Edits Moldorm to give the randomized item over spawning the Heart Container'''

        flow = self.readFile('DeguTail.bfevfl')
        item_key, item_index = self.getItemInfo('D1-moldorm')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event8', 'Event45')

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event16', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event19', self.songs_dict['BGM_PANEL_RESULT'])
            event_tools.setEventSong(flow.flowchart, 'Event65', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event30', self.songs_dict['BGM_DUNGEON_BOSS'])
        
        self.writeFile('DeguTail.bfevfl', flow)



    def genieChanges(self):
        '''Edits Genie to give the randomized item over spawning the Heart Container'''

        flow = self.readFile('PotDemonKing.bfevfl')
        item_key, item_index = self.getItemInfo('D2-genie')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event29', 'Event56')

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event5', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event53', self.songs_dict['BGM_PANEL_RESULT'])
            event_tools.setEventSong(flow.flowchart, 'Event50', self.songs_dict['BGM_DUNGEON_BOSS'])
        
        self.writeFile('PotDemonKing.bfevfl', flow)



    def slimeEyeChanges(self):
        '''Edits Slime Eye to give the randomized item over spawning the Heart Container'''

        flow = self.readFile('DeguZol.bfevfl')
        item_key, item_index = self.getItemInfo('D3-slime-eye')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event29', 'Event43')

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event17', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event36', self.songs_dict['BGM_PANEL_RESULT'])
            event_tools.setEventSong(flow.flowchart, 'Event32', self.songs_dict['BGM_DUNGEON_BOSS'])
        
        self.writeFile('DeguZol.bfevfl', flow)



    def anglerChanges(self):
        '''Edits Angler Fish to give the randomized item over spawning the Heart Container'''

        flow = self.readFile('Angler.bfevfl')
        item_key, item_index = self.getItemInfo('D4-angler')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event25', 'Event50')

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event5', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event28', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event29', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event51', self.songs_dict['BGM_PANEL_RESULT'])
        
        self.writeFile('Angler.bfevfl', flow)



    def slimeEelChanges(self):
        '''Edits Slime Eel to give the randomized item over spawning the Heart Container'''

        flow = self.readFile('Hooker.bfevfl')
        item_key, item_index = self.getItemInfo('D5-slime-eel')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event28', 'Event13')

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event26', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event33', self.songs_dict['BGM_PANEL_RESULT'])
            event_tools.setEventSong(flow.flowchart, 'Event49', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event20', self.songs_dict['BGM_DUNGEON_BOSS'])
        
        self.writeFile('Hooker.bfevfl', flow)



    def facadeChanges(self):
        '''Edits Facade to give the randomized item over spawning the Heart Container'''

        flow = self.readFile('MatFace.bfevfl')
        item_key, item_index = self.getItemInfo('D6-facade')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event8', 'Event35')

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event22', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event29', self.songs_dict['BGM_PANEL_RESULT'])
            event_tools.setEventSong(flow.flowchart, 'Event78', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event19', self.songs_dict['BGM_DUNGEON_BOSS'])
        
        self.writeFile('MatFace.bfevfl', flow)



    def eagleChanges(self):
        '''Edits Evil Eagle to give the randomized item over spawning the Heart Container'''

        flow = self.readFile('Albatoss.bfevfl')
        item_key, item_index = self.getItemInfo('D7-eagle')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event40', 'Event51')
        
        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event15', self.songs_dict['BGM_DUNGEON_LV7_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event20', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event66', self.songs_dict['BGM_PANEL_RESULT'])
        
        self.writeFile('Albatoss.bfevfl', flow)



    def hotheadChanges(self):
        '''Edits HotHead to give the randomized item over spawning the Heart Container'''

        flow = self.readFile('DeguFlame.bfevfl')
        item_key, item_index = self.getItemInfo('D8-hothead')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event13', 'Event15')

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event28', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event40', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event63', self.songs_dict['BGM_PANEL_RESULT'])
            event_tools.setEventSong(flow.flowchart, 'Event17', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event70', self.songs_dict['BGM_DUNGEON_BOSS'])
        
        self.writeFile('DeguFlame.bfevfl', flow)



    def lanmolaChanges(self):
        '''Edits Lanmola to give the randomized item over dropping the Angler Key'''

        flow = self.readFile('Lanmola.bfevfl')
        item_key, item_index = self.getItemInfo('lanmola')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event34', 'Event9')

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event2', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event18', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event22', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        
        self.writeFile('Lanmola.bfevfl', flow)



    def armosKnightChanges(self):
        '''Edits Armos Knight to open the doors before giving the randomized item'''

        flow = self.readFile('DeguArmos.bfevfl')
        event_tools.removeEventAfter(flow.flowchart, 'Event2')
        event_tools.insertEventAfter(flow.flowchart, 'Event2', 'Event8')
        item_key, item_index = self.getItemInfo('armos-knight')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event47', None)

        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event4', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event23', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        
        self.writeFile('DeguArmos.bfevfl', flow)



    def masterStalfosChanges(self):
        '''Edits Master Stalfos to give the randomized item over dropping the Hookshot'''

        flow = self.readFile('MasterStalfon.bfevfl')
        item_key, item_index = self.getItemInfo('D5-master-stalfos')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event37', 'Event194')
        
        if self.settings['randomize-music']:
            event_tools.setEventSong(flow.flowchart, 'Event0', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event1', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event3', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event132', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event157', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event2', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event4', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event10', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event23', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
        
        self.writeFile('MasterStalfon.bfevfl', flow)
    


    def syrupChanges(self):
        '''Edits the witch to give the randomized item instead of Magic Powder'''

        flow = self.readFile('Syrup.bfevfl')
        item_key, item_index = self.getItemInfo('syrup')
        item_get.insertItemGetAnimation(flow.flowchart, item_key, item_index, 'Event93', None)
        
        # if self.settings['randomize-music']:
        #     event_tools.setEventSong(flow.flowchart, 'Event56', self.songs_dict['BGM_SHOP_FAST'])
        #     event_tools.setEventSong(flow.flowchart, 'Event13', self.songs_dict['BGM_SHOP_FAST'])
        
        self.writeFile('Syrup.bfevfl', flow)
    


    def makeGeneralLEBChanges(self):
        """Fix some LEB files in ways that are always done, regardless of item placements"""

        ### Mad Batters: Give the batters a 3rd parameter for the event entry point to run
        # A: Bay
        if self.thread_active:
            room_data = self.readFile('MadBattersWell01_01A.leb')
            room_data.actors[2].parameters[2] = b'BatterA'
            self.writeFile('MadBattersWell01_01A.leb', room_data)

        # B: Woods
        if self.thread_active:
            room_data = self.readFile('MadBattersWell02_01A.leb')
            room_data.actors[6].parameters[2] = b'BatterB'
            self.writeFile('MadBattersWell02_01A.leb', room_data)

        # C: Mountain
        if self.thread_active:
            room_data = self.readFile('MadBattersWell03_01A.leb')
            room_data.actors[0].parameters[2] = b'BatterC'
            self.writeFile('MadBattersWell03_01A.leb', room_data)

        ### Lanmola Cave: Remove the AnglerKey actor
        if self.thread_active:
            room_data = self.readFile('LanmolaCave_02A.leb')
            room_data.actors.pop(5)
            self.writeFile('LanmolaCave_02A.leb', room_data)
        
        ### Classic D2: Turn the rock in front of Dungeon 2 into a swamp flower
        if self.settings['classic-d2'] and self.thread_active:
            room_data = self.readFile('Field_03E.leb')
            room_data.actors[12].type = 0x0E
            self.writeFile('Field_03E.leb', room_data)
        
        ### Remove the BoyA and BoyB cutscene after getting the FullMoonCello
        if self.thread_active:
            room_data = self.readFile('Field_12A.leb')

            # remove link between boy[1] and AreaEventBox[8]
            room_data.actors[1].relationships.x -= 1
            room_data.actors[1].relationships.section_1.pop(0)
            room_data.actors[8].relationships.y -=1
            room_data.actors[8].relationships.section_3.pop(0)

            self.writeFile('Field_12A.leb', room_data)

        ### Make Honeycomb show new graphics in tree, a different NPC key is used for when the player obtains the item
        if self.thread_active:
            room_data = self.readFile('Field_09H.leb')
            item_key, item_index, model_path, model_name = self.getItemInfo('tarin-ukuku', self.trap_models)
            room_data.actors[0].parameters[0] = bytes(model_path, 'utf-8')
            room_data.actors[0].parameters[1] = bytes(model_name, 'utf-8')

            self.writeFile('Field_09H.leb', room_data)
    


    def makeGeneralEventChanges(self):
        """Make changes to some events that should be in every seed, e.g. setting flags for having watched cutscenes"""
        
        ### PlayerStart event: Sets a bunch of flags for cutscenes being watched/triggered to prevent them from ever happening.
        ### First check if FirstClear is already set, to not do the work more than once and slightly slow down loading zones.
        if self.thread_active:
            flow = self.readFile('PlayerStart.bfevfl')
            player_start.makeStartChanges(flow.flowchart, self.settings)

            # skip over BGM_HOUSE_FIRST when Link wakes up because it overlaps with the shuffled zone BGM
            if self.settings['randomize-music']:
                event_tools.insertEventAfter(flow.flowchart, 'Event150', 'Event151')
            
            self.writeFile('PlayerStart.bfevfl', flow)

        # ### TreasureBox event: Adds in events to make certain items be progressive as well as custom events for other items.
        if self.thread_active:
            flow = self.readFile('TreasureBox.bfevfl')
            chests.writeChestEvent(flow.flowchart)
            if self.settings['fast-chests']:
                chests.makeChestsFaster(flow.flowchart)
            self.writeFile('TreasureBox.bfevfl', flow)

        ### ShellMansionPresent event: Similar to TreasureBox, must make some items progressive and add custom events for other items.
        if self.thread_active:
            flow = self.readFile('ShellMansionPresent.bfevfl')
            seashell_mansion.changeRewards(flow.flowchart)
            self.writeFile('ShellMansionPresent.bfevfl', flow)
        
        ### Item: Add and fix some entry points for the ItemGetSequence
        if self.thread_active:
            flow = self.readFile('Item.bfevfl')
            
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
            
            self.writeFile('Item.bfevfl', flow)
        
        ### MadamMeowMeow: Change her behaviour to always take back BowWow if you have him, and not do anything based on having the Horn
        if self.thread_active:
            flow = self.readFile('MadamMeowMeow.bfevfl')

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
            self.writeFile('MadamMeowMeow.bfevfl', flow)

        ### WindFishsEgg: Removes the Owl cutscene after opening the egg
        if self.thread_active:
            flow = self.readFile('WindFishsEgg.bfevfl')
            event_tools.insertEventAfter(flow.flowchart, 'Event142', None)
            self.writeFile('WindFishsEgg.bfevfl', flow)

        ### SkeletalGuardBlue: Make him sell 20 bombs in addition to the 20 powder
        if self.thread_active:
            flow = self.readFile('SkeletalGuardBlue.bfevfl')

            # edit Magic Powder amount from 20 to 40 so that it'll max even with the capacity upgrade
            event_tools.findEvent(flow.flowchart, 'Event19').data.params.data['count'] = 40
            
            # give 60 Bombs so that it'll max even with the capacity upgrade
            add_bombs = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItem',
                {'itemType': 4, 'count': 60, 'autoEquip': False})
            
            # check GetMagicPowder flag before buying
            # these guards will no longer be a source for getting your main powder, and cannot sell bombs until the player can buy powder
            if self.settings['shuffle-powder']:
                check_powder = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
                    {'symbol': 'GetMagicPowder'}, {0: 'Event54', 1: 'Event46'})
                event_tools.setSwitchEventCase(flow.flowchart, 'Event7', 1, check_powder)
            
            # check BombsFound flag when buying powder so we can give some additional resources if available
            # these guards are not a source for getting your main bombs
            if self.settings['shuffle-bombs']:
                check_bombs = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
                    {'symbol': data.BOMBS_FOUND_FLAG}, {0: None, 1: add_bombs})
                event_tools.insertEventAfter(flow.flowchart, 'Event19', check_bombs)
            else:
                event_tools.insertEventAfter(flow.flowchart, 'Event19', add_bombs)

        dungeon_item_setting = self.settings['dungeon-items']
        if dungeon_item_setting != 'none':
            event_defs = []

            # TODO: add the items through ASM when the level text is being displayed
            if dungeon_item_setting in ['mc', 'mcb']:
                event_defs += item_get.insertItemWithoutAnimation('DungeonMap', -1)
                event_defs += item_get.insertItemWithoutAnimation('Compass', -1)
            if dungeon_item_setting in ['stone-beak', 'mcb']:
                event_defs += item_get.insertItemWithoutAnimation('StoneBeak', -1)

            # Adding event on DungeonIn entrypoint
            event_tools.createActionChain(flow.flowchart, 'Event2', event_defs)

        self.writeFile('SkeletalGuardBlue.bfevfl', flow)

        ### Make Save&Quit after getting a GameOver send you back to Marin's house
        if self.thread_active:
            flow = self.readFile('Common.bfevfl')

            event_tools.setSwitchEventCase(flow.flowchart, 'Event64', 1,
                event_tools.createActionEvent(flow.flowchart, 'GameControl', 'RequestLevelJump',
                    {'level': 'Field', 'locator': 'Field_11C', 'offsetX': 0.0, 'offsetZ': 0.0},
                    'Event67'))
            
            # shuffle Rapids race music
            if self.settings['randomize-music']:
                # remove the music for now since it gets cut off due to something with setting the new BGM in the lvb file
                event_tools.insertEventAfter(flow.flowchart, 'Event167', None)
                #
                # event_tools.findEvent(flow.flowchart, 'Event78').data.params.data['label'] = self.songs_dict['BGM_RAFTING_TIMEATTACK']
            self.writeFile('Common.bfevfl', flow)
        
        ### PrizeCommon: Change the figure to look for when the fast-trendy setting is on, and makes Yoshi not replace Lens
        if self.thread_active:
            flow = self.readFile('PrizeCommon.bfevfl')
            crane_prizes.makeEventChanges(flow.flowchart, self.settings)
            self.writeFile('PrizeCommon.bfevfl', flow)



    def makeGeneralDatasheetChanges(self):
        """Make changes to some datasheets that are general in nature and not tied to specific item placements"""

        if self.thread_active:
            sheet = self.readFile('Npc.gsheet')
            for npc in sheet['values']:
                if not self.thread_active:
                    break
                npcs.makeNpcChanges(npc, self.placements, self.settings)
            
            npcs.makeNewNpcs(sheet, self.placements, self.item_defs)
            self.writeFile('Npc.gsheet', sheet)

        if self.thread_active:
            sheet = self.readFile('ItemDrop.gsheet')
            item_drops.makeDatasheetChanges(sheet, self.settings)
            self.writeFile('ItemDrop.gsheet', sheet)

        if self.thread_active:
            sheet = self.readFile('Items.gsheet')

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
            if self.settings['traps'] != 'none':
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

            self.writeFile('Items.gsheet', sheet)
        
        if self.thread_active:
            sheet = self.readFile('Conditions.gsheet')

            for condition in sheet['values']:
                if not self.thread_active:
                    break
                conditions.editConditions(condition, self.settings)
            
            conditions.makeConditions(sheet, self.placements)
            self.writeFile('Conditions.gsheet', sheet)

        if self.thread_active:
            sheet = self.readFile('CranePrize.gsheet')
            crane_prizes.makeDatasheetChanges(sheet, self.settings)
            self.writeFile('CranePrize.gsheet', sheet)
        
        if self.thread_active:
            group1 = self.readFile('CranePrizeFeaturedPrizeGroup1.gsheet')
            # group2 = self.readFile('CranePrizeFeaturedPrizeGroup2.gsheet')
            crane_prizes.changePrizeGroups(group1)
            self.writeFile('CranePrizeFeaturedPrizeGroup1.gsheet', group1)
            # self.writeFile('CranePrizeFeaturedPrizeGroup2.gsheet', group2)

        if self.thread_active:
            sheet = self.readFile('GlobalFlags.gsheet')
            sheet, self.global_flags = flags.makeFlags(sheet)
            self.writeFile('GlobalFlags.gsheet', sheet)
        
        if self.settings['fast-fishing'] and self.thread_active:
            sheet = self.readFile('FishingFish.gsheet')

            for fish in sheet['values']:
                if not self.thread_active:
                    break

                if len(fish['mOpenItem']) > 0:
                    fish['mOpenItem'] = 'ClothesGreen'
            
            self.writeFile('FishingFish.gsheet', sheet)
    


    def randomizeMusic(self):
        """Maps each BGM track to a new track
        
        This mapping is used in a couple places throughout when changing music"""
        
        bgms = list(copy.deepcopy(data.BGM_TRACKS))
        random.shuffle(bgms)

        # map each track to a new track using the duplicate list
        for i in data.BGM_TRACKS:
            ind = bgms.index(random.choice(bgms))
            self.songs_dict[i] = bgms.pop(ind)
            # print(i, self.songs_dict[i])
        
        # reset RNG so that other things that use it will be the same whether or not shuffled music is on
        random.seed(self.seed)
    


    def makeMusicChanges(self):
        """Replaces the BGM info in the lvb files with the shuffled songs"""

        levels_path = f'{self.rom_path}/region_common/level'
        folders = [f for f in os.listdir(levels_path) if not f.endswith('.ldb')]

        for folder in folders:
            if not self.thread_active:
                break

            level = self.readFile(f'{folder}.lvb')
            for zone in level.zones:
                if zone.bgm in self.songs_dict:
                    zone.bgm = self.songs_dict[zone.bgm]
            
            self.writeFile(f'{folder}.lvb', level)
        
        # edit music that is played through events
        if self.thread_active:
            self.makeEventMusicChanges()
    


    def makeEventMusicChanges(self):
        '''Goes through and randomizes the music controlled by events

        Also skips over some music that either would overlap or cut out otherwise
        
        Some were already handled when editing items. This focuses on the rest'''

        if self.thread_active:
            flow = self.readFile('Bossblin.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event64', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event68', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('Bossblin.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('BossBlob.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event19', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event12', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('BossBlob.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('Dodongo.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event5', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event43', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event3', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('Dodongo.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('DonPawn.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event21', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event30', self.songs_dict['BGM_PANEL_RESULT'])
            event_tools.setEventSong(flow.flowchart, 'Event38', self.songs_dict['BGM_DUNGEON_BOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_DUNGEON_BOSS'])
            self.writeFile('DonPawn.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('Gohma.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event0', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event1', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('Gohma.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('Hinox.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event37', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event55', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event1', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('Hinox.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('HiploopHover.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event38', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event7', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('HiploopHover.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('Jacky.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event37', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('Jacky.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('MightPunch.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event56', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('MightPunch.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('PiccoloMaster.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event48', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event53', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event3', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('PiccoloMaster.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('Rola.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event20', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event1', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('Rola.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('Shadow.bfevfl')
            # event_tools.setEventSong(flow.flowchart, 'Event6', self.songs_dict['BGM_LASTBOSS_DEMO_TEXT'])
            event_tools.setEventSong(flow.flowchart, 'Event37', self.songs_dict['BGM_LASTBOSS_WIN'])
            event_tools.setEventSong(flow.flowchart, 'Event60', self.songs_dict['BGM_LASTBOSS_BATTLE'])
            event_tools.setEventSong(flow.flowchart, 'Event71', self.songs_dict['BGM_LASTBOSS_BATTLE'])
            # event_tools.setEventSong(flow.flowchart, 'Event44', self.songs_dict['BGM_LASTBOSS_DEMO_TEXT'])
            self.writeFile('Shadow.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('StoneHinox.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event4', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event35', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            event_tools.setEventSong(flow.flowchart, 'Event29', self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'])
            self.writeFile('StoneHinox.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('ToolShopkeeper.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event87', self.songs_dict['BGM_DUNGEON_BOSS'])
            self.writeFile('ToolShopkeeper.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('TurtleRock.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event1', self.songs_dict['BGM_DUNGEON_LV8_ENT_BATTLE'])
            event_tools.setEventSong(flow.flowchart, 'Event26', self.songs_dict['BGM_DUNGEON_LV8_ENT_BATTLE'])
            event_tools.setEventSong(flow.flowchart, 'Event11', self.songs_dict['BGM_DUNGEON_LV8_ENT_BATTLE'])
            self.writeFile('TurtleRock.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('WindFish.bfevfl')
            event_tools.setEventSong(flow.flowchart, 'Event73', self.songs_dict['BGM_DEMO_AFTER_LASTBOSS'])
            # event_tools.setEventSong(flow.flowchart, 'Event101', self.songs_dict['BGM_DEMO_AFTER_LASTBOSS_WIND_FISH'])
            event_tools.setEventSong(flow.flowchart, 'Event74', self.songs_dict['BGM_DEMO_AFTER_LASTBOSS'])
            event_tools.setEventSong(flow.flowchart, 'Event93', self.songs_dict['BGM_LASTBOSS_WIN'])
            # event_tools.setEventSong(flow.flowchart, 'Event118', self.songs_dict['BGM_DEMO_AFTER_LASTBOSS_WIND_FISH'])
            self.writeFile('WindFish.bfevfl', flow)



    def makeGeneralARCChanges(self):
        """Replaces the Title Screen logo with the Randomizer logo"""

        try:
            # Creates the UI folder path
            if not os.path.exists(f'{self.romfs_dir}/region_common/ui'):
                os.makedirs(f'{self.romfs_dir}/region_common/ui')

            # Read the BNTX file from the sarc file and edit the title screen logo to include the randomizer logo
            sarc_data = self.readFile('StartUp.arc')
            bntx_tools.createRandomizerTitleScreenArchive(sarc_data)
            self.writeFile('StartUp.arc', sarc_data)
        except:
            # regardless of any errors, just consider this task done, the logo is not needed to play
            self.progress_value += 1
            self.progress_update.emit(self.progress_value)



    def makeInstrumentChanges(self):
        """Iterates through the Instrument rooms and edits the Instrument actor data"""

        # Open up the already modded SinkingSword eventflow to make new events
        flow = self.readFile('SinkingSword.bfevfl')
        
        for room in data.INSTRUMENT_ROOMS:
            if not self.thread_active:
                break

            room_data = self.readFile(f'{data.INSTRUMENT_ROOMS[room]}.leb')
            
            item_key, item_index, model_path, model_name = self.getItemInfo(room, self.dungeon_trap_models)

            if self.settings['shuffle-dungeons']:
                cur_dun = re.match('(.+)_\\d\\d[A-Z]', data.INSTRUMENT_ROOMS[room]).group(1)
                for k,v in data.DUNGEON_ENTRANCES.items():
                    dun = re.match('(.+)_\\d\\d[A-Z]', v[0]).group(1)
                    if dun == cur_dun:
                        ent_keys = list(self.placements['dungeon-entrances'].keys())
                        ent_values = list(self.placements['dungeon-entrances'].values())
                        d = data.DUNGEON_ENTRANCES[ent_keys[ent_values.index(k)]]
                        destination = d[2] + d[3]
            else:
                destination = None
            
            instruments.changeInstrument(flow.flowchart, item_key, item_index, model_path, model_name,
                room, room_data, destination)
            
            self.writeFile(f'{data.INSTRUMENT_ROOMS[room]}.leb', room_data)
        
        self.writeFile('SinkingSword.bfevfl', flow)



    def makeHeartPieceChanges(self):
        """Iterates through the nonsunken Heart Piece rooms and edits the Heart Piece actor data"""

        flow = self.readFile('SinkingSword.bfevfl')
        
        sunken = [
            'taltal-east-drop',
            'south-bay-sunken',
            'bay-passage-sunken',
            'river-crossing-cave',
            'kanalet-moat-south'
        ]
        non_sunken = (x for x in data.HEART_ROOMS if x not in sunken)
        
        for room in non_sunken:
            if not self.thread_active:
                break

            room_data = self.readFile(f'{data.HEART_ROOMS[room]}.leb')
            item_key, item_index, model_path, model_name = self.getItemInfo(room, self.trap_models)
            heart_pieces.changeHeartPiece(flow.flowchart, item_key, item_index, model_path, model_name, room, room_data)
            self.writeFile(f'{data.HEART_ROOMS[room]}.leb', room_data)
        
        self.writeFile('SinkingSword.bfevfl', flow)



    def makeTelephoneChanges(self):
        """Edits the telephone event file to allow the player to freely swap tunics
        
        [Not Implemented] Also adds rooster and bowwow to be able to get them back if companion shuffle is on"""

        flow = self.readFile('Telephone.bfevfl')
        tunic_swap.writeSwapEvents(flow.flowchart)
        self.writeFile('Telephone.bfevfl', flow)
        
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
    


    def makeLv10RupeeChanges(self):
        """Edits the room data for the 28 free standing rupees in Color Dungeon so they are randomized"""

        from RandomizerCore.Randomizers import rupees

        flow = self.readFile('SinkingSword.bfevfl')
        room_data = self.readFile('Lv10ClothesDungeon_08D.leb')
        
        for i in range(28):
            if self.thread_active:
                item_key, item_index, model_path, model_name = self.getItemInfo(f'D0-rupee-{i + 1}', self.dungeon_trap_models)
                room_data.setRupeeParams(model_path, model_name, f'Lv10Rupee_{i + 1}', item_key, i)
                rupees.makeEventChanges(flow.flowchart, i, item_key, item_index)
            else: break
        
        self.writeFile('Lv10ClothesDungeon_08D.leb', room_data)
        self.writeFile('SinkingSword.bfevfl', flow)



    def makeShopChanges(self):
        """Edits the shop items datasheet as well as event files relating to buying/stealing
        
        NOT FINISHED!!!
        
        This needs ASM to set the GettingFlag of the stolen items"""

        if self.thread_active:
            sheet = self.readFile('ShopItem.gsheet')
            shop.makeDatasheetChanges(sheet, self.placements, self.item_defs)
            self.writeFile('ShopItem.gsheet', sheet)
        
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
            flow = self.readFile('QuadrupletsMother.bfevfl')
            trade_quest.mamashaChanges(flow.flowchart, self.getItemInfo('mamasha'))
            self.writeFile('QuadrupletsMother.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('RibbonBowWow.bfevfl')
            trade_quest.ciaociaoChanges(flow.flowchart, self.getItemInfo('ciao-ciao'))
            self.writeFile('RibbonBowWow.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('Sale.bfevfl')
            trade_quest.saleChanges(flow.flowchart, self.getItemInfo('sale'))
            self.writeFile('Sale.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('Kiki.bfevfl')
            item_key, item_index, model_path, model_name = self.getItemInfo('kiki', self.trap_models)
            trade_quest.kikiChanges(flow.flowchart, self.settings, item_key, item_index)
            # # shuffle bridge building music
            # if self.settings['randomize-music']:
            #     event_tools.findEvent(flow.flowchart, 'Event114').data.params.data['label'] = self.songs_dict['BGM_EVENT_MONKEY']
            #     event_tools.addForkEventForks(flow.flowchart, 'Event102', [
            #         event_tools.createActionEvent(flow.flowchart, 'Audio', 'StopBGM',
            #             {'label': self.songs_dict['BGM_EVENT_MONKEY'], 'duration': 0.0})
            #     ])
            self.writeFile('Kiki.bfevfl', flow)
            room_data = self.readFile('Field_08L.leb')
            kiki_actor = room_data.actors[0]
            stick_actor = room_data.actors[7]
            # move kiki & the stick if open-bridge is on
            if self.settings['open-bridge']:
                kiki_actor.posX += 1.5
                stick_actor.posX += 1.5
                stick_actor.posZ -= 1.5
            # add the model info to the stick actor parameters
            stick_actor.parameters[1] = bytes(model_path, 'utf-8')
            stick_actor.parameters[2] = bytes(model_name, 'utf-8')
            self.writeFile('Field_08L.leb', room_data)

        if self.thread_active:
            flow = self.readFile('Tarin.bfevfl')
            trade_quest.tarinChanges(flow.flowchart, self.getItemInfo('tarin-ukuku'))
            # # shuffle bees music
            # if self.settings['randomize-music']:
            #     event_tools.findEvent(flow.flowchart, 'Event113').data.params.data['label'] = self.songs_dict['BGM_EVENT_BEE']
            self.writeFile('Tarin.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('ChefBear.bfevfl')
            trade_quest.chefChanges(flow.flowchart, self.getItemInfo('chef-bear'))
            self.writeFile('ChefBear.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('Papahl.bfevfl')
            trade_quest.papahlChanges(flow.flowchart, self.getItemInfo('papahl'))
            self.writeFile('Papahl.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('Christine.bfevfl')
            trade_quest.christineChanges(flow.flowchart, self.getItemInfo('christine-trade'))
            self.writeFile('Christine.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('DrWrite.bfevfl')
            trade_quest.mrWriteChanges(flow.flowchart, self.getItemInfo('mr-write'))
            self.writeFile('DrWrite.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('GrandmaUlrira.bfevfl')
            trade_quest.grandmaYahooChanges(flow.flowchart, self.getItemInfo('grandma-yahoo'))
            self.writeFile('GrandmaUlrira.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('MarthasBayFisherman.bfevfl')
            trade_quest.fishermanChanges(flow.flowchart, self.getItemInfo('bay-fisherman'))
            self.writeFile('MarthasBayFisherman.bfevfl', flow)

        if self.thread_active:
            flow = self.readFile('MermaidMartha.bfevfl')
            trade_quest.mermaidChanges(flow.flowchart, self.getItemInfo('mermaid-martha'))
            self.writeFile('MermaidMartha.bfevfl', flow)
        
        if self.thread_active:
            flow = self.readFile('MarthaStatue.bfevfl')
            trade_quest.statueChanges(flow.flowchart)
            self.writeFile('MarthaStatue.bfevfl', flow)
    


    def makeOwlStatueChanges(self):
        '''Edits the eventflows for the owl statues to give items, as well as one extra level file'''

        if self.thread_active: # put the slime key check on the owl for now
            flow = self.readFile('FieldOwlStatue.bfevfl')
            owls.addSlimeKeyCheck(flow.flowchart)
            if self.settings['owl-overworld-gifts']:
                owls.makeFieldChanges(flow.flowchart, self.placements, self.item_defs)
            self.writeFile('FieldOwlStatue.bfevfl', flow)
        
        if self.settings['owl-dungeon-gifts']:
            if self.thread_active:
                flow = self.readFile('DungeonOwlStatue.bfevfl')
                owls.makeDungeonChanges(flow.flowchart, self.placements, self.item_defs)
                self.writeFile('DungeonOwlStatue.bfevfl', flow)
            
            if self.thread_active:
                room_data = self.readFile('Lv01TailCave_04B.leb')
                room_data.actors[0].parameters[0] = bytes('examine_Tail04B', 'utf-8')
                self.writeFile('Lv01TailCave_04B.leb', room_data)
            
            if self.thread_active:
                room_data = self.readFile('Lv10ClothesDungeon_06C.leb')
                room_data.actors[9].parameters[0] = bytes('examine_Color06C', 'utf-8')
                self.writeFile('Lv10ClothesDungeon_06C.leb', room_data)

            if self.thread_active:
                room_data = self.readFile('Lv10ClothesDungeon_07D.leb')
                room_data.actors[4].parameters[0] = bytes('examine_Color07D', 'utf-8')
                self.writeFile('Lv10ClothesDungeon_07D.leb', room_data)

            if self.thread_active:
                room_data = self.readFile('Lv10ClothesDungeon_05F.leb')
                room_data.actors[4].parameters[0] = bytes('examine_Color05F', 'utf-8')
                self.writeFile('Lv10ClothesDungeon_05F.leb', room_data)
    


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



    def randomizeEnemies(self):
        """Randomizes enemy actors that do not affect logic
        Needed kills are left vanilla and potentially problematic enemies are excluded"""

        from RandomizerCore.Randomizers import enemies
        from RandomizerCore.randomizer_data import ENEMY_DATA

        land_ids = []
        air_ids = []
        water_ids = []
        water2D_ids = []
        water_shallow_ids = []
        tree_ids = []
        hole_ids = []

        for value in ENEMY_DATA['Actors'].values():
            if value['type'] == 'land':
                land_ids.append(value['id'])
            elif value['type'] == 'air':
                air_ids.append(value['id'])
            elif value['type'] == 'water':
                water_ids.append(value['id'])
            elif value['type'] == 'water2D':
                water2D_ids.append(value['id'])
            elif value['type'] == 'water-shallow':
                water_shallow_ids.append(value['id'])
            elif value['type'] == 'tree':
                tree_ids.append(value['id'])
            elif value['type'] == 'hole':
                hole_ids.append(value['id'])
        
        no_vire = list(air_ids[:])
        no_vire.remove(0x26)
        restrictions = (-1, 0x3, 0x15, 0x16)
        
        enemy_ids = {
            'land': land_ids,
            'air': air_ids,
            'no_vire': no_vire,
            'water': water_ids,
            'water2D': water2D_ids,
            'water_shallow': water_shallow_ids,
            'tree': tree_ids,
            'hole': hole_ids,
            'restr': restrictions
        }

        enemy_settings = {
            'types': self.settings['randomize-enemies'],
            'sizes':self.settings['randomize-enemy-sizes']
        }

        levels_path = f'{self.rom_path}/region_common/level'
        included_folders = ENEMY_DATA['Included_Folders']
        folders = [f for f in os.listdir(levels_path) if f in included_folders]
        
        num_of_mods = 0
        random.seed(self.seed) # restart the rng so that enemies will be the same regardless of settings

        for folder in folders:
            if not self.thread_active:
                break

            files = [f for f in os.listdir(f'{levels_path}/{folder}') if f.endswith('.leb')]

            for file in files:
                if not self.thread_active:
                    break

                room_data = self.readFile(file)
                
                rand_state, edited_room =\
                    enemies.shuffleEnemyActors(room_data, folder, file, enemy_ids, enemy_settings, random.getstate())
                
                random.setstate(rand_state)
                
                if edited_room:
                    self.writeFile(f'{file}', room_data)
                    num_of_mods += 1
        
        if IS_RUNNING_FROM_SOURCE:
            print(f'Num of modded files for enemizer: {num_of_mods}')
    


    def shuffleDungeons(self):
        """Shuffles the entrances of each dungeon"""

        ent_keys = list(self.placements['dungeon-entrances'].keys())
        ent_values = list(self.placements['dungeon-entrances'].values())

        for k,v in data.DUNGEON_ENTRANCES.items():

            ######################################################################## - dungeon in
            if not self.thread_active:
                break

            room_data = self.readFile(f'{v[2]}.leb')
                        
            d = data.DUNGEON_ENTRANCES[self.placements['dungeon-entrances'][k]]
            destin = d[0] + d[1]
            room_data.setLoadingZoneTarget(destin, v[4])

            self.writeFile(f'{v[2]}.leb', room_data)
            
            ######################################################################## - dungeon out
            if not self.thread_active:
                break

            room_data = self.readFile(f'{v[0]}.leb')
            
            d = data.DUNGEON_ENTRANCES[ent_keys[ent_values.index(k)]]
            destin = d[2] + d[3]
            room_data.setLoadingZoneTarget(destin, 0)

            self.writeFile(f'{v[0]}.leb', room_data)



    def shuffleDungeonIcons(self):
        """Shuffle the dungeon icons so that players can use the in-game map to track dungeon entrances"""

        icon_keys = list(data.DUNGEON_MAP_ICONS.keys())
        icon_values = list(data.DUNGEON_MAP_ICONS.values())
        maps = [i[0] for i in icon_values]
        sheet = self.readFile('UiFieldMapIcons.gsheet')
        for icon in sheet['values']:
            if not self.thread_active:
                break

            if icon['mNameLabel'] in maps:
                k = icon_keys[maps.index(icon['mNameLabel'])]
                new_k = self.placements['dungeon-entrances'][k]
                icon['mNameLabel'] = data.DUNGEON_MAP_ICONS[new_k][0]
                icon['mFirstShowFlagName'] = data.DUNGEON_MAP_ICONS[new_k][1]
        
        self.writeFile('UiFieldMapIcons.gsheet', sheet)



    def changeLevelConfigs(self):
        """Edits the config of the lvb files for dungeons to allow companions"""

        levels_path = f'{self.rom_path}/region_common/level'

        # allow companions inside every dungeon
        # exception being the Egg since companions can collide with Nightmare and cause a softlock
        folders = [f for f in os.listdir(levels_path) if f.startswith('Lv') and not f.startswith('Lv09')]

        for folder in folders:
            if not self.thread_active:
                break
            
            level = self.readFile(f'{folder}.lvb')
            level.config.allow_companions = True
            self.writeFile(f'{folder}.lvb', level)
    


    def makeExefsPatches(self):
        """Creates the necessary exefs_patches for the Randomizer to work correctly"""
        
        base_bid = 'AE16F71E002AF8CB059A9A74C4D90F34BA984892'
        update_bid = '909E904AF78AC1B8DEEFE97AB2CCDB51968f0EC7'
        patcher = assemble.createRandomizerPatches(random.getstate(), self.settings)
        
        # output the ASM as .ips for console, and .pchtxt for emulator
        if self.settings['platform'] == 'console':
            self.writeFile(f'{base_bid}.ips', patcher.generateIPS32Patch())
            self.writeFile(f'{update_bid}.ips', patcher.generateIPS32Patch())
        else:
            self.writeFile('1.0.0.pchtxt', patcher.generatePCHTXT(base_bid))
            self.writeFile('1.0.1.pchtxt', patcher.generatePCHTXT(update_bid))



    def fixWaterLoadingZones(self):
        """Changes each water loading zone to be deactivated until the player has flippers
        
        This is to prevent the player from potentially softlocking by entering them with the rooster"""

        for room in data.WATER_LOADING_ZONES:
            if not self.thread_active:
                break

            room_data = self.readFile(f'{room}.leb')

            for actor in data.WATER_LOADING_ZONES[room]:
                room_data.actors[actor].switches[0] = (1, self.global_flags['FlippersFound'])
            
            self.writeFile(f'{room}.leb', room_data)



    def fixRapidsRespawn(self):
        """If the player reloads an autosave after completing the Rapids Race without flippers,
        they will drown and then be sent to 0,0,0 in an endless falling loop

        This is fixed by iterating over every touching water tile, and prevent reloading on them"""

        rooms_to_fix = (
            'Field_09N',
            'Field_09O',
            'Field_09P',
            'Field_10P',
        )

        for room in rooms_to_fix:
            if not self.thread_active:
                break

            # we want to edit the grid info, which is skipped over by default since we mostly leave it untouched
            # so we have readFile() early return the path, and read the Room data here with edit_grid=True
            room_path = self.readFile(f'{room}.leb', return_path=True)
            with open(room_path, 'rb') as f:
                room_data = leb.Room(f.read(), edit_grid=True)

            for tile in room_data.grid.tilesdata:
                if tile.flags3['iswaterlava']:
                    tile.flags3['respawnload'] = 0

            self.writeFile(f'{room}.leb', room_data)



    def openMabe(self):
        """Removes grass / monsters / rocks that block access to go outside of Mabe village"""

        rooms_to_fix = {
            'Field_10A': [0x624A97005CD29205],
            'Field_10E': [0x62000A005D15AC9E, 0x620015005D15AC9E],
            'Field_15B': [0x7200BB005CFF3740, 0x7200B9005CFF3740],
            'Field_15C': [0x7200DC005CFF3741, 0x7200D6005CFF3741],
        }

        for room, elements_to_remove in rooms_to_fix.items():
            if not self.thread_active:
                break

            room_data = self.readFile(f'{room}.leb')

            for element_key in elements_to_remove:
                for index, actor in enumerate(room_data.actors):
                    if actor.key == element_key:
                        room_data.actors.pop(index)
                        break

            self.writeFile(f'{room}.leb', room_data)



    def getItemInfo(self, check, trap_models=None):
        item = self.placements[check]
        item_key = self.item_defs[item]['item-key']
        item_index = self.placements['indexes'][check] if check in self.placements['indexes'] else -1

        if trap_models is None:
            return item_key, item_index
        
        if item_key[-4:] != 'Trap':
            model_path = self.item_defs[item]['model-path']
            model_name = self.item_defs[item]['model-name']
        else:
            model_name = random.choice(list(trap_models))
            model_path = trap_models[model_name]
        
        return item_key, item_index, model_path, model_name



    def readFile(self, file_name: str, return_path=False):
        """Reads the given file from the rom path, or the output path if it already exists"""

        dir = self.getRelativeDir(file_name)

        file_path = f'{self.romfs_dir}/{dir}/{file_name}'
        if file_name not in self.out_files:
            file_path = f'{self.rom_path}/{dir}/{file_name}'
        
        if return_path:
            return file_path
        
        if file_name.endswith('bfevfl'):
            return event_tools.readFlow(file_path)
        elif file_name.endswith('gsheet'):
            return oead_tools.readSheet(file_path)
        elif file_name.endswith('arc'):
            return oead_tools.SARC(file_path)
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        if file_name.endswith('leb'):
            return leb.Room(file_data)
        elif file_name.endswith('lvb'):
            return lvb.Level(file_data)



    def writeFile(self, file_name: str, data):
        """Writes the file to the output and updates the progress bar"""

        if not self.thread_active:
            return
        
        dir = self.getRelativeDir(file_name)
        if dir is not None:
            file_path = f'{self.romfs_dir}/{dir}/{file_name}'
        else:
            file_path = f'{self.exefs_dir}/{file_name}'
        
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        if file_name.endswith('bfevfl'):
            event_tools.writeFlow(file_path, data)
        elif file_name.endswith('gsheet'):
            oead_tools.writeSheet(file_path, data)
        elif file_name.endswith(('leb', 'lvb', 'arc')):
            with open(file_path, 'wb') as f:
                f.write(data.repack())
        else:
            with open(file_path, 'wb') as f:
                f.write(data)
        
        self.out_files.add(file_name)
        self.progress_value += 1
        self.progress_update.emit(self.progress_value)



    def getRelativeDir(self, file_name):
        """Reads the file_name to determine the directory relative to the romfs"""

        if file_name.endswith('leb'):
            dir = f'region_common/level/{file_name.split("_")[0]}'
        elif file_name.endswith('lvb'):
            dir = f'region_common/level/{file_name.split(".")[0]}'
        elif file_name.endswith('gsheet'):
            dir = 'region_common/datasheets'
        elif file_name.endswith('bfevfl'):
            dir = 'region_common/event'
        elif file_name.endswith('arc'):
            dir = 'region_common/ui'
        else:
            return None
        
        return dir
