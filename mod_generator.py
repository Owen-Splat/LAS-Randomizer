from PySide6 import QtCore

import os
import re
import copy
import random
import traceback

import Tools.leb as leb
import Tools.oead_tools as oead_tools
import Tools.event_tools as event_tools
from Tools.patcher import Patcher

from Randomizers import actors, chests, conditions, crane_prizes, dampe, data, fishing, flags, golden_leaves, heart_pieces
from Randomizers import instruments, item_drops, item_get, mad_batter, marin, miscellaneous, npcs, owls, patches
from Randomizers import player_start, rapids, seashell_mansion, small_keys, tarin, trade_quest, tunic_swap

from randomizer_paths import RESOURCE_PATH




class ModsProcess(QtCore.QThread):
    
    progress_update = QtCore.Signal(int)
    is_done = QtCore.Signal()
    error = QtCore.Signal(str)

    
    def __init__(self, placements, rom_path, out_dir, items, seed, parent=None):
        QtCore.QThread.__init__(self, parent)

        self.placements = placements
        self.rom_path = rom_path
        self.out_dir = out_dir
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
        self.seed = seed
        random.seed(seed)

        self.global_flags = {}
        self.songs_dict = {} 

        self.progress_value = 0
        self.thread_active = True
    
    

    # STOP THREAD
    def stop(self):
        self.thread_active = False
    
    
    
    # automatically called when this thread is started
    def run(self):
        try:
            if self.placements['settings']['randomize-music'] and self.thread_active:
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
            
            if self.placements['settings']['free-book'] and self.thread_active:
                self.setFreeBook()
            
            if self.placements['settings']['blup-sanity'] and self.thread_active:
                self.makeLv10RupeeChanges()
            
            if self.placements['settings']['randomize-music'] and self.thread_active:
                self.makeMusicChanges()
            
            if self.placements['settings']['bad-pets'] and self.thread_active:
                self.changeLevelConfigs()
            
            if self.placements['settings']['randomize-enemies'] and self.thread_active:
                self.randomizeEnemies()
            
            if self.placements['settings']['shuffled-dungeons'] and self.thread_active:
                self.shuffleDungeons()
                self.shuffleDungeonIcons()
            
            # if self.thread_active: self.fixWaterLoadingZones()

            # current asm does not appear to break anything, can finally include :)
            if self.thread_active: self.makeExefsPatches()

            if self.thread_active: os.mkdir(f'{self.out_dir}/01006BB00C6F0000')
        
        except Exception:
            er = traceback.format_exc()
            print(er)
            self.error.emit(er)
        
        finally: # regardless if there was an error or not, we want to tell the progress window that this thread has finished
            # print(self.progress_value)
            self.is_done.emit()
    


    def makeChestContentFixes(self):
        """Patch LEB files of rooms with chests to update their contents"""
        
        # Start by setting up the paths for the RomFS
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level')
        
        chest_sizes = copy.deepcopy(data.CHEST_SIZES)
        if self.placements['settings']['scaled-chest-sizes']:
            # if all seashell and trade gift locations are set to junk, set chests that contain them to be small, otherwise big
            if not self.placements['settings']['seashells-important']:
                chest_sizes['seashell'] = 0.8
            if not self.placements['settings']['trade-important']:
                chest_sizes['trade'] = 0.8
        else:
            for k in chest_sizes:
                chest_sizes[k] = 1.0 # if scaled chest sizes is off, set every value to normal size
        
        for room in data.CHEST_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', data.CHEST_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                
                with open(f'{self.rom_path}/region_common/level/{dirname}/{data.CHEST_ROOMS[room]}.leb', 'rb') as roomfile:
                    room_data = leb.Room(roomfile.read())

                item_key = self.item_defs[self.placements[room]]['item-key']
                item_index = self.placements['indexes'][room] if room in self.placements['indexes'] else -1
                item_type = self.item_defs[self.placements[room]]['type']
                size = chest_sizes[item_type]
                
                if room == 'taltal-5-chest-puzzle':
                    for i in range(5):
                        room_data.setChestContent(item_key, item_index, i, size)
                else:
                    room_data.setChestContent(item_key, item_index, chest_size=size)
                
                if item_key == 'BowWow':
                    pass
                elif item_key == 'Rooster':
                    room_data.addChestRooster()
                
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.CHEST_ROOMS[room]}.leb', 'wb') as outfile:
                        outfile.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
                
                # Two special cases in D7 have duplicate rooms, once for pre-collapse and once for post-collapse. So we need to make sure we write the same data to both rooms.
                if room == 'D7-grim-creeper':
                    with open(f'{self.rom_path}/region_common/level/Lv07EagleTower/Lv07EagleTower_06H.leb', 'rb') as roomfile:
                        room_data = leb.Room(roomfile.read())

                    room_data.setChestContent(item_key, item_index, chest_size=size)
                    
                    if item_key == 'BowWow':
                        pass
                    elif item_key == 'Rooster':
                        room_data.addChestRooster()

                    if self.thread_active:
                        with open(f'{self.out_dir}/Romfs/region_common/level/Lv07EagleTower/Lv07EagleTower_06H.leb', 'wb') as outfile:
                            outfile.write(room_data.repack())
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)

                if room == 'D7-3f-horseheads':
                    with open(f'{self.rom_path}/region_common/level/Lv07EagleTower/Lv07EagleTower_05G.leb', 'rb') as roomfile:
                        room_data = leb.Room(roomfile.read())

                    room_data.setChestContent(item_key, item_index, chest_size=size)
                    
                    if item_key == 'BowWow':
                        pass
                    elif item_key == 'Rooster':
                        room_data.addChestRooster()

                    if self.thread_active:
                        with open(f'{self.out_dir}/Romfs/region_common/level/Lv07EagleTower/Lv07EagleTower_05G.leb', 'wb') as outfile:
                            outfile.write(room_data.repack())
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)
            else: break



    def makeSmallKeyChanges(self):
        """Patch SmallKey event and LEB files for rooms with small key drops to change them into other items"""

        # Start by setting up the paths for the RomFS
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level')

        # Open up the SmallKey event to be ready to edit
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/SmallKey.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        small_keys.makeKeysFaster(flow.flowchart)
        # small_keys.writeSunkenKeyEvent(flow.flowchart)

        trap_models = copy.deepcopy(data.ITEM_MODELS)
        trap_models.update({
            'SmallKey': 'ItemSmallKey.bfres',
            'NightmareKey': 'ItemNightmareKey.bfres',
            'StoneBeak': 'ItemStoneBeak.bfres',
            'Compass': 'ItemCompass.bfres',
            'DungeonMap': 'ItemDungeonMap.bfres'
        })
        
        for i in self.placements['starting-items']:
            i = self.item_defs[i]['item-key']
            if i == 'SwordLv1':
                i = 'SinkingSword'
            if i in ['SinkingSword', 'Shield', 'PowerBraceletLv1']:
                if self.placements['starting-items'].count(i) < 2:
                    continue
            if i in trap_models:
                del trap_models[i]
        
        if not self.placements['settings']['shuffle-instruments']:
            for i in self.instruments:
                if i in trap_models:
                    del trap_models[i]

        for room in data.SMALL_KEY_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', data.SMALL_KEY_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')

                with open(f'{self.rom_path}/region_common/level/{dirname}/{data.SMALL_KEY_ROOMS[room]}.leb', 'rb') as roomfile:
                    room_data = leb.Room(roomfile.read())
                
                item = self.placements[room]
                item_key = self.item_defs[item]['item-key']
                item_index = self.placements['indexes'][room] if room in self.placements['indexes'] else -1

                if item_key[-4:] != 'Trap':
                    model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
                    model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
                else:
                    model_name = random.choice(list(trap_models))
                    model_path = trap_models[model_name]
                    if room == 'pothole-final': # reroll the trap model if it's a dungeon item
                        while model_name in ('SmallKey', 'NightmareKey', 'StoneBeak', 'Compass', 'DungeonMap'):
                            model_name = random.choice(list(trap_models))
                            model_path = trap_models[model_name]
                
                if room == 'pothole-final': # change slime key into a small key
                    act = room_data.actors[42]
                    act.type = 0xa9 # small key
                    act.posX += 1.5 # move right one tile
                    act.posZ -= 1.5 # move up one tile
                    act.switches[0] = (1, self.global_flags['PotholeKeySpawn']) # index of PotholeKeySpawn
                    act.switches[1] = (1, self.global_flags['PotholeGet']) # index of PotholeGet
                
                small_keys.writeKeyEvent(flow.flowchart, item_key, item_index, room)
                room_data.setSmallKeyParams(model_path, model_name, room, item_key)

                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.SMALL_KEY_ROOMS[room]}.leb', 'wb') as outfile:
                        outfile.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)

                if room == 'D4-sunken-item': # special case. need to write the same data in 06A
                    with open(f'{self.rom_path}/region_common/level/Lv04AnglersTunnel/Lv04AnglersTunnel_06A.leb', 'rb') as roomfile:
                        room_data = leb.Room(roomfile.read())
                
                    room_data.setSmallKeyParams(model_path, model_name, room, item_key)
                    
                    if self.thread_active:
                        with open(f'{self.out_dir}/Romfs/region_common/level/Lv04AnglersTunnel/Lv04AnglersTunnel_06A.leb', 'wb') as outfile:
                            outfile.write(room_data.repack())
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)
            
            else: break
        
        if self.thread_active:
            self.makeGoldenLeafChanges(flow)
        


    def makeGoldenLeafChanges(self, flow):
        '''Make small key actors spawn for the golden leaf checks'''

        trap_models = copy.deepcopy(data.ITEM_MODELS)
        
        for i in self.placements['starting-items']:
            i = self.item_defs[i]['item-key']
            if i == 'SwordLv1':
                i = 'SinkingSword'
            if i in ['SinkingSword', 'Shield', 'PowerBraceletLv1']:
                if self.placements['starting-items'].count(i) < 2:
                    continue
            if i in trap_models:
                del trap_models[i]
        
        if not self.placements['settings']['shuffle-instruments']:
            for inst in self.instruments:
                if inst in trap_models:
                    del trap_models[inst]
        
        for room in data.GOLDEN_LEAF_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', data.GOLDEN_LEAF_ROOMS[room]).group(1)

                with open(f'{self.rom_path}/region_common/level/{dirname}/{data.GOLDEN_LEAF_ROOMS[room]}.leb', 'rb') as f:
                    room_data = leb.Room(f.read())
                
                item = self.placements[room]
                item_key = self.item_defs[item]['item-key']
                item_index = self.placements['indexes'][room] if room in self.placements['indexes'] else -1

                if item_key[-4:] != 'Trap':
                    model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
                    model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
                else:
                    model_name = random.choice(list(trap_models))
                    model_path = trap_models[model_name]
                
                golden_leaves.createRoomKey(room_data, room, self.global_flags)
                small_keys.writeKeyEvent(flow.flowchart, item_key, item_index, room)
                room_data.setSmallKeyParams(model_path, model_name, room, item_key)

                if self.thread_active:
                    if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                        os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.GOLDEN_LEAF_ROOMS[room]}.leb', 'wb') as f:
                        f.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
            
            else: break
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SmallKey.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



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
        ### Event changes
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Tarin.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        tarin.makeEventChanges(flow.flowchart, self.placements, self.item_defs)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Tarin.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def sinkingSwordChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/SinkingSword.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        # actors.addCompanionActors(flow.flowchart, self.rom_path)

        # Beach
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/Field'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/Field')

        with open(f'{self.rom_path}/region_common/level/Field/Field_16C.leb', 'rb') as file:
            room = leb.Room(file.read())
        
        item = self.placements['washed-up']
        item_key = self.item_defs[item]['item-key']
        item_index = self.placements['indexes']['washed-up'] if 'washed-up' in self.placements['indexes'] else -1

        trap_models = copy.deepcopy(data.ITEM_MODELS)
        
        for i in self.placements['starting-items']:
            i = self.item_defs[i]['item-key']
            if i == 'SwordLv1':
                i = 'SinkingSword'
            if i in ['SinkingSword', 'Shield', 'PowerBraceletLv1']:
                if self.placements['starting-items'].count(i) < 2:
                    continue
            if i in trap_models:
                del trap_models[i]
        
        if not self.placements['settings']['shuffle-instruments']:
            for inst in self.instruments:
                if inst in trap_models:
                    del trap_models[inst]

        if item_key[-4:] != 'Trap':
            model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
            model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
        else:
            model_name = random.choice(list(trap_models))
            model_path = trap_models[model_name]
        
        music_shuffled = self.placements['settings']['randomize-music'] # remove some music that would get cut off
        miscellaneous.changeSunkenSword(flow.flowchart, item_key, item_index, model_path, model_name, room, music_shuffled)

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/Field/Field_16C.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ########################################################################################################################
        # Rooster Cave (bird key)
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/EagleKeyCave'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/EagleKeyCave')

        with open(f'{self.rom_path}/region_common/level/EagleKeyCave/EagleKeyCave_01A.leb', 'rb') as file:
            room = leb.Room(file.read())
        
        item = self.placements['taltal-rooster-cave']
        item_key = self.item_defs[item]['item-key']
        item_index = self.placements['indexes']['taltal-rooster-cave'] if 'taltal-rooster-cave' in self.placements['indexes'] else -1

        if item_key[-4:] != 'Trap':
            model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
            model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
        else:
            model_name = random.choice(list(trap_models))
            model_path = trap_models[model_name]
        
        miscellaneous.changeBirdKey(flow.flowchart, item_key, item_index, model_path, model_name, room)

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/EagleKeyCave/EagleKeyCave_01A.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ##########################################################################################################################
        # Dream Shrine (ocarina)
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/DreamShrine'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/DreamShrine')

        with open(f'{self.rom_path}/region_common/level/DreamShrine/DreamShrine_01A.leb', 'rb') as file:
            room = leb.Room(file.read())
        
        item = self.placements['dream-shrine-left']
        item_key = self.item_defs[item]['item-key']
        item_index = self.placements['indexes']['dream-shrine-left'] if 'dream-shrine-left' in self.placements['indexes'] else -1

        if item_key[-4:] != 'Trap':
            model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
            model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
        else:
            model_name = random.choice(list(trap_models))
            model_path = trap_models[model_name]
        
        miscellaneous.changeOcarina(flow.flowchart, item_key, item_index, model_path, model_name, room)

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/DreamShrine/DreamShrine_01A.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ##########################################################################################################################
        # Woods (mushroom)
        with open(f'{self.rom_path}/region_common/level/Field/Field_06A.leb', 'rb') as file:
            room = leb.Room(file.read())
        
        item = self.placements['woods-loose']
        item_key = self.item_defs[item]['item-key']
        item_index = self.placements['indexes']['woods-loose'] if 'woods-loose' in self.placements['indexes'] else -1

        if item_key[-4:] != 'Trap':
            model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
            model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
        else:
            model_name = random.choice(list(trap_models))
            model_path = trap_models[model_name]
        
        miscellaneous.changeMushroom(flow.flowchart, item_key, item_index, model_path, model_name, room)

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/Field/Field_06A.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ##########################################################################################################################
        # Mermaid Cave (lens)
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/MermaidStatue'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/MermaidStatue')

        with open(f'{self.rom_path}/region_common/level/MermaidStatue/MermaidStatue_01A.leb', 'rb') as file:
            room = leb.Room(file.read())
        
        item = self.placements['mermaid-cave']
        item_key = self.item_defs[item]['item-key']
        item_index = self.placements['indexes']['mermaid-cave'] if 'mermaid-cave' in self.placements['indexes'] else -1

        if item_key[-4:] != 'Trap':
            model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
            model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
        else:
            model_name = random.choice(list(trap_models))
            model_path = trap_models[model_name]
        
        miscellaneous.changeLens(flow.flowchart, item_key, item_index, model_path, model_name, room)
        
        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/MermaidStatue/MermaidStatue_01A.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        #########################################################################################################################
        # Done!
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def walrusChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Walrus.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['walrus'] if 'walrus' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['walrus']]['item-key'],
            item_index, 'Event53', 'Event110')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Walrus.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def christineChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Christine.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['christine-grateful'] if 'christine-grateful' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['christine-grateful']]['item-key'],
            item_index, 'Event44', 'Event36')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Christine.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def invisibleZoraChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/SecretZora.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['invisible-zora'] if 'invisible-zora' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['invisible-zora']]['item-key'],
            item_index, 'Event23', 'Event27')

        event_tools.insertEventAfter(flow.flowchart, 'Event32', 'Event23')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SecretZora.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def marinChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Marin.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        if self.placements['settings']['fast-songs']: # skip the cutscene if fast-songs is enabled
            
            # Remove Link holding the ocarina and make him sad that you chose to skip such a beautiful song :(
            sad_face = event_tools.createActionEvent(flow.flowchart, 'Link', 'SetFacialExpression',
                {'expression': 'sad'}, None)
            
            flag_set = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
                {'symbol': 'MarinsongGet', 'value': True}, sad_face)
            event_tools.insertEventAfter(flow.flowchart, 'Event92', flag_set)

            item_index = self.placements['indexes']['marin'] if 'marin' in self.placements['indexes'] else -1
            item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['marin']]['item-key'],
                item_index, sad_face, 'Event666')
        
        else:
            item_index = self.placements['indexes']['marin'] if 'marin' in self.placements['indexes'] else -1
            item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['marin']]['item-key'],
                item_index, 'Event246', 'Event666')
            
        marin.makeEventChanges(flow)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Marin.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def ghostRewardChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Owl.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        new = event_tools.createActionEvent(flow.flowchart, 'Owl', 'Destroy', {})

        item_index = self.placements['indexes']['ghost-reward'] if 'ghost-reward' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['ghost-reward']]['item-key'],
            item_index, 'Event34', new)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Owl.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def clothesFairyChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/FairyQueen.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D0-fairy-2'] if 'D0-fairy-2' in self.placements['indexes'] else -1
        item2 = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D0-fairy-2']]['item-key'],
            item_index, 'Event0', 'Event180')

        item_index = self.placements['indexes']['D0-fairy-1'] if 'D0-fairy-1' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D0-fairy-1']]['item-key'],
            item_index, 'Event0', item2)

        event_tools.insertEventAfter(flow.flowchart, 'Event128', 'Event58')

        # make the fairy queen send the player to the proper exit if Shuffled Dungeons is on
        if self.placements['settings']['shuffled-dungeons']:
            ent_keys = list(self.placements['dungeon-entrances'].keys())
            ent_values = list(self.placements['dungeon-entrances'].values())
            d = data.DUNGEON_ENTRANCES[ent_keys[ent_values.index('color-dungeon')]]
            destin = d[2] + d[3]
            warp_event = event_tools.findEvent(flow.flowchart, 'Event37')
            warp_event.data.params.data['level'] = re.match('(.+)_\\d\\d[A-Z]', destin).group(1)
            warp_event.data.params.data['locator'] = destin
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/FairyQueen.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def goriyaChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Goriya.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': data.GORIYA_FLAG, 'value': True}, 'Event4')

        item_index = self.placements['indexes']['goriya-trader'] if 'goriya-trader' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['goriya-trader']]['item-key'],
            item_index, 'Event87', flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': data.GORIYA_FLAG}, {0: 'Event7', 1: 'Event15'})
        event_tools.insertEventAfter(flow.flowchart, 'Event24', flag_check)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Goriya.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def manboChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ManboTamegoro.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': data.MANBO_FLAG, 'value': True}, 'Event13')
        
        if self.placements['settings']['fast-songs']: # skip the cutscene if fast-songs is enabled
            before_item = 'Event44'
        else:
            before_item = 'Event31'
        
        item_index = self.placements['indexes']['manbo'] if 'manbo' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['manbo']]['item-key'],
            item_index, before_item, flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.MANBO_FLAG}, {0: 'Event37', 1: 'Event35'})
        event_tools.insertEventAfter(flow.flowchart, 'Event9', flag_check)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ManboTamegoro.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def mamuChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Mamu.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': data.MAMU_FLAG, 'value': True}, 'Event40')
        
        if self.placements['settings']['fast-songs']: # skip the cutscene if fast-songs is enabled
            before_item = 'Event55'
        else:
            before_item = 'Event85'
        
        item_index = self.placements['indexes']['mamu'] if 'mamu' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['mamu']]['item-key'],
            item_index, before_item, flag_event)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.MAMU_FLAG}, {0: 'Event14', 1: 'Event98'})
        event_tools.insertEventAfter(flow.flowchart, 'Event10', flag_check)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Mamu.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def rapidsChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/RaftShopMan.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        rapids.makePrizesStack(flow.flowchart, self.placements, self.item_defs)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/RaftShopMan.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def fishingChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Fisherman.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        fishing.makeEventChanges(flow.flowchart, self.placements, self.item_defs)
        # fishing.fixFishingBottle(flow.flowchart)
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Fisherman.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def trendyChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/GameShopOwner.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['trendy-prize-final'] if 'trendy-prize-final' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['trendy-prize-final']]['item-key'],
            item_index, 'Event112', 'Event239')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/GameShopOwner.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def seashellMansionChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ShellMansionMaster.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['5-seashell-reward'] if '5-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event36').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['5-seashell-reward']]['item-key'], 'itemIndex': item_index, 'flag': 'GetSeashell10'}

        item_index = self.placements['indexes']['15-seashell-reward'] if '15-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event10').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['15-seashell-reward']]['item-key'], 'itemIndex': item_index, 'flag': 'GetSeashell20'}

        item_index = self.placements['indexes']['30-seashell-reward'] if '30-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event11').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['30-seashell-reward']]['item-key'], 'itemIndex': item_index, 'flag': 'GetSeashell30'}

        item_index = self.placements['indexes']['50-seashell-reward'] if '50-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event13').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['50-seashell-reward']]['item-key'], 'itemIndex': item_index, 'flag': 'GetSeashell50'}

        item_index = self.placements['indexes']['40-seashell-reward'] if '40-seashell-reward' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['40-seashell-reward']]['item-key'], item_index, 'Event91', 'Event79')

        seashell_mansion.makeEventChanges(flow.flowchart, self.placements)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ShellMansionMaster.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def madBatterChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MadBatter.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['mad-batter-bay'] if 'mad-batter-bay' in self.placements['indexes'] else -1
        item1 = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['mad-batter-bay']]['item-key'], item_index, None, 'Event23')

        item_index = self.placements['indexes']['mad-batter-woods'] if 'mad-batter-woods' in self.placements['indexes'] else -1
        item2 = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['mad-batter-woods']]['item-key'], item_index, None, 'Event23')

        item_index = self.placements['indexes']['mad-batter-taltal'] if 'mad-batter-taltal' in self.placements['indexes'] else -1
        item3 = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['mad-batter-taltal']]['item-key'], item_index, None, 'Event23')

        mad_batter.writeEvents(flow, item1, item2, item3)

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event18').data.params.data['label'] = self.songs_dict['BGM_MADBATTER']
            event_tools.findEvent(flow.flowchart, 'Event150').data.params.data['label'] = self.songs_dict['BGM_MADBATTER'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MadBatter.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def dampeChanges(self):
        sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/MapPieceClearReward.gsheet')

        # Page 1 reward
        dampe.makeDatasheetChanges(sheet, 3,
        self.item_defs[self.placements['dampe-page-1']]['item-key'],
        self.placements['indexes']['dampe-page-1'] if 'dampe-page-1' in self.placements['indexes'] else -1,
        'DampePage1')

        # Page 2 reward
        dampe.makeDatasheetChanges(sheet, 7,
        self.item_defs[self.placements['dampe-page-2']]['item-key'],
        self.placements['indexes']['dampe-page-2'] if 'dampe-page-2' in self.placements['indexes'] else -1,
        'DampePage2')

        # Final reward
        dampe.makeDatasheetChanges(sheet, 12,
        self.item_defs[self.placements['dampe-final']]['item-key'],
        self.placements['indexes']['dampe-final'] if 'dampe-final' in self.placements['indexes'] else -1,
        'DampeFinal')

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/MapPieceClearReward.gsheet', sheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #######

        sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/MapPieceTheme.gsheet')

        # 1-4 reward - heart challenge
        dampe.makeDatasheetChanges(sheet, 3,
        self.item_defs[self.placements['dampe-heart-challenge']]['item-key'],
        self.placements['indexes']['dampe-heart-challenge'] if 'dampe-heart-challenge' in self.placements['indexes'] else -1,
        'DampeHeart')

        # 3-2 reward - bottle challenge
        dampe.makeDatasheetChanges(sheet, 9,
        self.item_defs[self.placements['dampe-bottle-challenge']]['item-key'],
        self.placements['indexes']['dampe-bottle-challenge'] if 'dampe-bottle-challenge' in self.placements['indexes'] else -1,
        'DampeBottle')

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/MapPieceTheme.gsheet', sheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        #######

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Danpei.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        dampe.makeEventChanges(flow.flowchart)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Danpei.bfevfl', flow)



    def moldormChanges(self):
        '''Edits Moldorm to give the randomized item over spawning the Heart Container'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguTail.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D1-moldorm'] if 'D1-moldorm' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D1-moldorm']]['item-key'], item_index, 'Event8', 'Event45')

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event16').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event19').data.params.data['label'] = self.songs_dict['BGM_PANEL_RESULT']
            event_tools.findEvent(flow.flowchart, 'Event35').data.params.data['label'] = self.songs_dict['BGM_FANFARE_BOSS_HEART_GET']
            event_tools.findEvent(flow.flowchart, 'Event65').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event30').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguTail.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def genieChanges(self):
        '''Edits Genie to give the randomized item over spawning the Heart Container'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/PotDemonKing.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D2-genie'] if 'D2-genie' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D2-genie']]['item-key'], item_index, 'Event29', 'Event56')

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event5').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event6').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event25').data.params.data['label'] = self.songs_dict['BGM_FANFARE_BOSS_HEART_GET']
            event_tools.findEvent(flow.flowchart, 'Event53').data.params.data['label'] = self.songs_dict['BGM_PANEL_RESULT']
            event_tools.findEvent(flow.flowchart, 'Event50').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/PotDemonKing.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def slimeEyeChanges(self):
        '''Edits Slime Eye to give the randomized item over spawning the Heart Container'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguZol.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D3-slime-eye'] if 'D3-slime-eye' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D3-slime-eye']]['item-key'], item_index, 'Event29', 'Event43')

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event17').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event28').data.params.data['label'] = self.songs_dict['BGM_FANFARE_BOSS_HEART_GET']
            event_tools.findEvent(flow.flowchart, 'Event36').data.params.data['label'] = self.songs_dict['BGM_PANEL_RESULT']
            event_tools.findEvent(flow.flowchart, 'Event32').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguZol.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def anglerChanges(self):
        '''Edits Angler Fish to give the randomized item over spawning the Heart Container'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Angler.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D4-angler'] if 'D4-angler' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D4-angler']]['item-key'], item_index, 'Event25', 'Event50')

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event5').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event24').data.params.data['label'] = self.songs_dict['BGM_FANFARE_BOSS_HEART_GET']
            event_tools.findEvent(flow.flowchart, 'Event28').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event29').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event51').data.params.data['label'] = self.songs_dict['BGM_PANEL_RESULT']
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Angler.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def slimeEelChanges(self):
        '''Edits Slime Eel to give the randomized item over spawning the Heart Container'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Hooker.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D5-slime-eel'] if 'D5-slime-eel' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D5-slime-eel']]['item-key'], item_index, 'Event28', 'Event13')

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event14').data.params.data['label'] = self.songs_dict['BGM_DEFEAT_LOOP']
            event_tools.findEvent(flow.flowchart, 'Event24').data.params.data['label'] = self.songs_dict['BGM_FANFARE_BOSS_HEART_GET']
            event_tools.findEvent(flow.flowchart, 'Event26').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event33').data.params.data['label'] = self.songs_dict['BGM_PANEL_RESULT']
            event_tools.findEvent(flow.flowchart, 'Event49').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event20').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event73').data.params.data['label'] = self.songs_dict['BGM_DEFEAT_LOOP'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Hooker.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def facadeChanges(self):
        '''Edits Facade to give the randomized item over spawning the Heart Container'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MatFace.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D6-facade'] if 'D6-facade' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D6-facade']]['item-key'], item_index, 'Event8', 'Event35')

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event5').data.params.data['label'] = self.songs_dict['BGM_DEFEAT_LOOP']
            event_tools.findEvent(flow.flowchart, 'Event7').data.params.data['label'] = self.songs_dict['BGM_FANFARE_BOSS_HEART_GET']
            event_tools.findEvent(flow.flowchart, 'Event22').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event29').data.params.data['label'] = self.songs_dict['BGM_PANEL_RESULT']
            event_tools.findEvent(flow.flowchart, 'Event78').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event6').data.params.data['label'] = self.songs_dict['BGM_DEFEAT_LOOP'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event19').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MatFace.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def eagleChanges(self):
        '''Edits Evil Eagle to give the randomized item over spawning the Heart Container'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Albatoss.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D7-eagle'] if 'D7-eagle' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D7-eagle']]['item-key'], item_index, 'Event40', 'Event51')
        
        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event15').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_LV7_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event20').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event39').data.params.data['label'] = self.songs_dict['BGM_FANFARE_BOSS_HEART_GET']
            event_tools.findEvent(flow.flowchart, 'Event66').data.params.data['label'] = self.songs_dict['BGM_PANEL_RESULT']
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Albatoss.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def hotheadChanges(self):
        '''Edits HotHead to give the randomized item over spawning the Heart Container'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguFlame.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D8-hothead'] if 'D8-hothead' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D8-hothead']]['item-key'], item_index, 'Event13', 'Event15')

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event12').data.params.data['label'] = self.songs_dict['BGM_FANFARE_BOSS_HEART_GET']
            event_tools.findEvent(flow.flowchart, 'Event18').data.params.data['label'] = self.songs_dict['BGM_DEFEAT_LOOP']
            event_tools.findEvent(flow.flowchart, 'Event28').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event40').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event63').data.params.data['label'] = self.songs_dict['BGM_PANEL_RESULT']
            event_tools.findEvent(flow.flowchart, 'Event17').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event19').data.params.data['label'] = self.songs_dict['BGM_DEFEAT_LOOP'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event70').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguFlame.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def lanmolaChanges(self):
        '''Edits Lanmola to give the randomized item over dropping the Angler Key'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Lanmola.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['lanmola'] if 'lanmola' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['lanmola']]['item-key'], item_index, 'Event34', 'Event9')

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event2').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event18').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event22').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Lanmola.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def armosKnightChanges(self):
        '''Edits Armos Knight to open the doors before giving the randomized item'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguArmos.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        event_tools.removeEventAfter(flow.flowchart, 'Event2')
        event_tools.insertEventAfter(flow.flowchart, 'Event2', 'Event8')


        item_index = self.placements['indexes']['armos-knight'] if 'armos-knight' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['armos-knight']]['item-key'], item_index, 'Event47', None)

        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event4').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event23').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguArmos.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def masterStalfosChanges(self):
        '''Edits Master Stalfos to give the randomized item over dropping the Hookshot'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MasterStalfon.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['D5-master-stalfos'] if 'D5-master-stalfos' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D5-master-stalfos']]['item-key'],
            item_index, 'Event37', 'Event194')
        
        if self.placements['settings']['randomize-music']:
            event_tools.findEvent(flow.flowchart, 'Event0').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event1').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event3').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event132').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event157').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event2').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event4').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event10').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event23').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MasterStalfon.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
    


    def syrupChanges(self):
        '''Edits the witch to give the randomized item instead of Magic Powder'''

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Syrup.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item_index = self.placements['indexes']['syrup'] if 'syrup' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['syrup']]['item-key'],
            item_index, 'Event93', None)
        
        # if self.placements['settings']['randomize-music']:
        #     event_tools.findEvent(flow.flowchart, 'Event56').data.params.data['label'] = self.songs_dict['BGM_SHOP_FAST']
        #     event_tools.findEvent(flow.flowchart, 'Event13').data.params.data['label'] = self.songs_dict['BGM_SHOP_FAST'] # StopBGM
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Syrup.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
    


    def makeGeneralLEBChanges(self):
        """Fix some LEB files in ways that are always done, regardless of item placements"""

        ### Entrance to Mysterious Forest: Set the owl to 0 instead of 1, prevents the cutscene from triggering in some circumstances.
        # For all other owls, setting the flags is sufficient but this one sucks.
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/Field'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/Field')
        
        if self.thread_active:
            with open(f'{self.rom_path}/region_common/level/Field/Field_09A.leb', 'rb') as file:
                room = leb.Room(file.read())

            room.actors[1].parameters[0] = 0

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/Field/Field_09A.leb', 'wb') as file:
                    file.write(room.repack())
                    self.progress_value += 1 # update progress bar
                    self.progress_update.emit(self.progress_value)

        ### Mad Batters: Give the batters a 3rd parameter for the event entry point to run
        # A: Bay
        if self.thread_active:
            if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell01'):
                os.makedirs(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell01')

            with open(f'{self.rom_path}/region_common/level/MadBattersWell01/MadBattersWell01_01A.leb', 'rb') as roomfile:
                room_data = leb.Room(roomfile.read())

            room_data.actors[2].parameters[2] = b'BatterA'

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell01/MadBattersWell01_01A.leb', 'wb') as outfile:
                    outfile.write(room_data.repack())
                    self.progress_value += 1 # update progress bar
                    self.progress_update.emit(self.progress_value)

        # B: Woods
        if self.thread_active:
            if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell02'):
                os.makedirs(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell02')

            with open(f'{self.rom_path}/region_common/level/MadBattersWell02/MadBattersWell02_01A.leb', 'rb') as roomfile:
                room_data = leb.Room(roomfile.read())

            room_data.actors[6].parameters[2] = b'BatterB'

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell02/MadBattersWell02_01A.leb', 'wb') as outfile:
                    outfile.write(room_data.repack())
                    self.progress_value += 1 # update progress bar
                    self.progress_update.emit(self.progress_value)

        # C: Mountain
        if self.thread_active:
            if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell03'):
                os.makedirs(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell03')

            with open(f'{self.rom_path}/region_common/level/MadBattersWell03/MadBattersWell03_01A.leb', 'rb') as roomfile:
                room_data = leb.Room(roomfile.read())

            room_data.actors[0].parameters[2] = b'BatterC'

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell03/MadBattersWell03_01A.leb', 'wb') as outfile:
                    outfile.write(room_data.repack())
                    self.progress_value += 1 # update progress bar
                    self.progress_update.emit(self.progress_value)

        ### Lanmola Cave: Remove the AnglerKey actor
        if self.thread_active:
            if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/LanmolaCave'):
                os.makedirs(f'{self.out_dir}/Romfs/region_common/level/LanmolaCave')

            with open(f'{self.rom_path}/region_common/level/LanmolaCave/LanmolaCave_02A.leb', 'rb') as roomfile:
                room_data = leb.Room(roomfile.read())

            room_data.actors.pop(5) # remove angler key

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/LanmolaCave/LanmolaCave_02A.leb', 'wb') as outfile:
                    outfile.write(room_data.repack())
                    self.progress_value += 1 # update progress bar
                    self.progress_update.emit(self.progress_value)
        
        ### Classic D2: Turn the rock in front of Dungeon 2 into a swamp flower
        if self.placements['settings']['classic-d2'] and self.thread_active:
            with open(f'{self.rom_path}/region_common/level/Field/Field_03E.leb', 'rb') as f:
                room_data = leb.Room(f.read())
            
            room_data.actors[12].type = 0x0E # 14

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/Field/Field_03E.leb', 'wb') as f:
                    f.write(room_data.repack())
                    self.progress_value += 1 # update progress bar
                    self.progress_update.emit(self.progress_value)
        
        ### Remove the BoyA and BoyB cutscene after getting the FullMoonCello
        if self.thread_active:
            with open(f'{self.rom_path}/region_common/level/Field/Field_12A.leb', 'rb') as f:
                room_data = leb.Room(f.read())
            
            # remove link between boy[1] and AreaEventBox[8]
            room_data.actors[1].relationships.x -= 1
            room_data.actors[1].relationships.section_1.pop(0)
            room_data.actors[8].relationships.y -=1
            room_data.actors[8].relationships.section_3.pop(0)

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/Field/Field_12A.leb', 'wb') as f:
                    f.write(room_data.repack())
                    self.progress_value += 1 # update progress bar
                    self.progress_update.emit(self.progress_value)

        ### Make Honeycomb show new graphics in tree, a different NPC key is used for when the player obtains the item
        if self.thread_active:
            with open(f'{self.rom_path}/region_common/level/Field/Field_09H.leb', 'rb') as f:
                room_data = leb.Room(f.read())
        
            item = self.placements['tarin-ukuku']
            item_key = self.item_defs[item]['item-key']

            if item_key[-4:] != 'Trap':
                model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
                model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
            else:
                trap_models = copy.deepcopy(data.ITEM_MODELS)
                
                for i in self.placements['starting-items']:
                    i = self.item_defs[i]['item-key']
                    if i == 'SwordLv1':
                        i = 'SinkingSword'
                    if i in ['SinkingSword', 'Shield', 'PowerBraceletLv1']:
                        if self.placements['starting-items'].count(i) < 2:
                            continue
                    if i in trap_models:
                        del trap_models[i]
                
                if not self.placements['settings']['shuffle-instruments']:
                    for inst in self.instruments:
                        if inst in trap_models:
                            del trap_models[inst]

                model_name = random.choice(list(trap_models))
                model_path = trap_models[model_name]

            room_data.actors[0].parameters[0] = bytes(model_path, 'utf-8')
            room_data.actors[0].parameters[1] = bytes(model_name, 'utf-8')

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/Field/Field_09H.leb', 'wb') as f:
                        f.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
    


    def makeGeneralEventChanges(self):
        """Make changes to some events that should be in every seed, e.g. setting flags for having watched cutscenes"""
        
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/event'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/event')

        ### PlayerStart event: Sets a bunch of flags for cutscenes being watched/triggered to prevent them from ever happening.
        ### First check if FirstClear is already set, to not do the work more than once and slightly slow down loading zones.
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/PlayerStart.bfevfl')
            actors.addNeededActors(flow.flowchart, self.rom_path)
            player_start.makeStartChanges(flow.flowchart, self.placements['settings'])

            # skip over BGM_HOUSE_FIRST when Link wakes up because it overlaps with the shuffled zone BGM
            if self.placements['settings']['randomize-music']:
                event_tools.insertEventAfter(flow.flowchart, 'Event150', 'Event151')
            
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/PlayerStart.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        # ### TreasureBox event: Adds in events to make certain items be progressive as well as custom events for other items.
        if self.thread_active:
            treasure_flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/TreasureBox.bfevfl')
            actors.addNeededActors(treasure_flow.flowchart, self.rom_path)
            # actors.addCompanionActors(treasure_flow.flowchart, self.rom_path)
            chests.writeChestEvent(treasure_flow.flowchart)
            chests.makeChestsFaster(treasure_flow.flowchart)
            flow_control_actor = event_tools.findActor(treasure_flow.flowchart, 'FlowControl') # store this to add to ShellMansionPresent

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/TreasureBox.bfevfl', treasure_flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### ShellMansionPresent event: Similar to TreasureBox, must make some items progressive and add custom events for other items.
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ShellMansionPresent.bfevfl')
            actors.addNeededActors(flow.flowchart, self.rom_path)
            flow.flowchart.actors.append(flow_control_actor)

            seashell_mansion.changeRewards(flow.flowchart, treasure_flow.flowchart)

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ShellMansionPresent.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ### Item: Add and fix some entry points for the ItemGetSequence
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Item.bfevfl')
            actors.addNeededActors(flow.flowchart, self.rom_path)
            
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

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Item.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ### MadamMeowMeow: Change her behaviour to always take back BowWow if you have him, and not do anything based on having the Horn
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MadamMeowMeow.bfevfl')

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

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MadamMeowMeow.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### WindFishsEgg: Removes the Owl cutscene after opening the egg
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/WindFishsEgg.bfevfl')
            event_tools.insertEventAfter(flow.flowchart, 'Event142', None)

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/WindFishsEgg.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### SkeletalGuardBlue: Make him sell 20 bombs in addition to the 20 powder
        if self.placements['settings']['reduce-farming'] and self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/SkeletalGuardBlue.bfevfl')

            event_tools.findEvent(flow.flowchart, 'Event19').data.params.data['count'] = 40 # still gives 20 w/o capacity upgrade
            
            add_bombs = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItem',
                {'itemType': 4, 'count': 60, 'autoEquip': False})
            
            # check GetMagicPowder flag before buying
            # these guards will no longer be a source for getting your main powder, and cannot sell bombs until the player can buy powder
            if self.placements['settings']['shuffle-powder']:
                check_powder = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
                    {'symbol': 'GetMagicPowder'}, {0: 'Event54', 1: 'Event46'})
                event_tools.setSwitchEventCase(flow.flowchart, 'Event7', 1, check_powder)
            
            # check BombsFound flag when buying powder so we can give some additional resources if available
            # these guards are not a source for getting your main bombs
            if self.placements['settings']['shuffle-bombs']:
                check_bombs = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
                    {'symbol': data.BOMBS_FOUND_FLAG}, {0: None, 1: add_bombs})
                event_tools.insertEventAfter(flow.flowchart, 'Event19', check_bombs)
            else:
                event_tools.insertEventAfter(flow.flowchart, 'Event19', add_bombs)
            
            ###################
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SkeletalGuardBlue.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### Make Save&Quit after getting a GameOver send you back to Marin's house
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Common.bfevfl')
            actors.addNeededActors(flow.flowchart, self.rom_path)

            event_tools.setSwitchEventCase(flow.flowchart, 'Event64', 1,
                event_tools.createActionEvent(flow.flowchart, 'GameControl', 'RequestLevelJump',
                    {'level': 'Field', 'locator': 'Field_11C', 'offsetX': 0.0, 'offsetZ': 0.0},
                    'Event67'))
            
            # shuffle Rapids race music
            if self.placements['settings']['randomize-music']:
                # remove the music for now since it gets cut off due to something with setting the new BGM in the lvb file
                event_tools.insertEventAfter(flow.flowchart, 'Event167', None)
                #
                # event_tools.findEvent(flow.flowchart, 'Event78').data.params.data['label'] = self.songs_dict['BGM_RAFTING_TIMEATTACK']

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Common.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ### PrizeCommon: Change the figure to look for when the fast-trendy setting is on, and makes Yoshi not replace Lens
        if self.thread_active:
            prize = event_tools.readFlow(f'{self.rom_path}/region_common/event/PrizeCommon.bfevfl')
            actors.addNeededActors(prize.flowchart, self.rom_path)
            prize.flowchart.actors.append(flow_control_actor)
            
            crane_prizes.makeEventChanges(prize.flowchart, self.placements['settings'])

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/PrizeCommon.bfevfl', prize)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)



    def makeGeneralDatasheetChanges(self):
        """Make changes to some datasheets that are general in nature and not tied to specific item placements"""

        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/datasheets'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/datasheets')

        ### Npc datasheet: Change MadBatter to use actor parameter $2 as its event entry point.
        ### Also change ItemSmallKey and ObjSinkingSword to use custom models/entry points.
        ### Change ItemClothesGreen to have the small key model, which we'll kinda hack in the Items datasheet so small keys are visible 
        ### in the GenericItemGetSequence
        ### same thing with ItemClothesRed for yoshi doll actors (instruments and ocarina)
        ### Make Papahl appear in the mountains after trading for the pineapple instead of the getting the Bell
        if self.thread_active:
            sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/Npc.gsheet')
            for npc in sheet['values']:
                if self.thread_active:
                    npcs.makeNpcChanges(npc, self.placements)
            npcs.makeNewNpcs(sheet)
                    
            if self.thread_active:
                oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/Npc.gsheet', sheet)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### ItemDrop datasheet: remove HeartContainer drops 0-7, HookShot drop, AnglerKey and FaceKey drops.
        if self.thread_active:
            sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/ItemDrop.gsheet')
            item_drops.makeDatasheetChanges(sheet, self.placements)

            if self.thread_active:
                oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/ItemDrop.gsheet', sheet)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### Items datasheet: Set npcKeys so certain items will show something when you get them.
        if self.thread_active:
            sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/Items.gsheet')

            trap = None
            for item in sheet['values']:
                if self.thread_active:
                    if item['symbol'] == 'Flippers': # Make getting Flippers set this custom flag for water loading zones to use
                        item['gettingFlag'] == 'FlippersFound'
                        continue
                    
                    if item['symbol'] == 'SmallKey':
                        item['npcKey'] = 'ItemClothesGreen'
                        continue
                    
                    if item['symbol'] == 'YoshiDoll': # this is for ocarina and instruments as they are ItemYoshiDoll actors
                        item['npcKey'] = 'ItemClothesRed'
                        trap = oead_tools.parseStruct(item) # keep a dict of this to use as a base for traps
                        continue
                    
                    if item['symbol'] == 'Honeycomb': # Honeycomb actor graphics are changed, so assign new npcKey for correct get graphics
                        item['npcKey'] = 'PatchHoneycomb'
                    
                else: break
            
            if trap is not None: # create entries for traps, seashell mansion gives a green rupee if the item isn't in this
                trap['symbol'] = 'ZapTrap'
                trap['itemID'] = 127
                sheet['values'].append(oead_tools.dictToStruct(trap))
                trap['symbol'] = 'DrownTrap'
                trap['itemID'] = 128
                sheet['values'].append(oead_tools.dictToStruct(trap))
                trap['symbol'] = 'SquishTrap'
                trap['itemID'] = 129
                sheet['values'].append(oead_tools.dictToStruct(trap))
            
            if self.thread_active:
                oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/Items.gsheet', sheet)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ### Conditions datasheet: Makes needed changes to conditions, as well as creating new ones for seashell sensor
        if self.thread_active:
            sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/Conditions.gsheet')

            for condition in sheet['values']:
                if self.thread_active:
                    conditions.editConditions(condition, self.placements, self.item_defs)
                else: break
            
            conditions.makeConditions(sheet, self.placements)
            
            if self.thread_active:
                oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/Conditions.gsheet', sheet)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### CranePrize datasheet: Makes general changes to prize conditions that are necessary
        if self.thread_active:
            sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/CranePrize.gsheet')
            crane_prizes.makeDatasheetChanges(sheet, self.placements, self.item_defs)
            # print(oead_tools.parseStructArray(sheet['values']))

            if self.thread_active:
                oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/CranePrize.gsheet', sheet)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ### Prize Groups: Removes Yoshi Doll from being a featured prize. This lets use control it by a flag instead of inventory
        group1 = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/CranePrizeFeaturedPrizeGroup1.gsheet')
        # group2 = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/CranePrizeFeaturedPrizeGroup2.gsheet')

        crane_prizes.changePrizeGroups(group1)

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/CranePrizeFeaturedPrizeGroup1.gsheet', group1)
            # oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/CranePrizeFeaturedPrizeGroup2.gsheet', group2)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### GlobalFlags datasheet: Add new flags to use
        if self.thread_active:
            sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/GlobalFlags.gsheet')
            sheet, self.global_flags = flags.makeFlags(sheet)

            if self.thread_active:
                oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/GlobalFlags.gsheet', sheet)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ### FishingFish datasheet: Remove the instrument requirements
        if self.placements['settings']['fast-fishing'] and self.thread_active:
            sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/FishingFish.gsheet')

            for fish in sheet['values']:
                if self.thread_active:
                    if len(fish['mOpenItem']) > 0:
                        fish['mOpenItem'] = 'ClothesGreen'
                else: break
            
            if self.thread_active:
                oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/FishingFish.gsheet', sheet)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
    


    def setFreeBook(self):
        """Set the event for the book of dark secrets to reveal the egg path without having the magnifying lens"""

        book = event_tools.readFlow(f'{self.rom_path}/region_common/event/Book.bfevfl')

        event_tools.insertEventAfter(book.flowchart, 'Event18', 'Event73')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Book.bfevfl', book)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
    


    def randomizeMusic(self):
        """Maps each BGM track to a new track
        
        This mapping is used in a couple places throughout when changing music"""
        
        ### Change the BGM entry in the level info files (.lvb) to a new BGM
        bgms = list(copy.deepcopy(data.BGM_TRACKS)) # make a duplicate list of the tracks tuple and shuffle it
        random.shuffle(bgms)

        # map each track to a new track using the duplicate list
        for i in data.BGM_TRACKS:
            ind = bgms.index(random.choice(bgms))
            self.songs_dict[i] = bgms.pop(ind)
            # print(i, self.songs_dict[i])
    


    def makeMusicChanges(self):
        """Replaces the BGM info in the lvb files with the shuffled songs"""

        from Randomizers import music
        
        levels_path = f'{self.rom_path}/region_common/level'
        out_path = f'{self.out_dir}/Romfs/region_common/level'

        folders = [f for f in os.listdir(levels_path) if not f.endswith('.ldb')]

        for folder in folders:
            if self.thread_active:
                with open(f'{levels_path}/{folder}/{folder}.lvb', 'rb') as f:
                    f_data = f.read()
                
                f_data = music.shuffleLevelBGMS(f_data, self.songs_dict)
                
                if not os.path.exists(f'{out_path}/{folder}'): # make the output folder if it does not already exist
                    os.makedirs(f'{out_path}/{folder}')
            
            if self.thread_active:
                with open(f'{out_path}/{folder}/{folder}.lvb', 'wb') as f: # write the new data to the output
                    f.write(f_data)
                    self.progress_value += 1 # update progress bar
                    self.progress_update.emit(self.progress_value)
        
        ### edit bgms that are played through events
        if self.thread_active:
            self.makeEventMusicChanges()
    


    def makeEventMusicChanges(self):
        '''Goes through and randomizes the music controlled by events

        Also skips over some music that either would overlap or cut out otherwise
        
        Some were already handled when editing items. This focuses on the rest'''

        ### Bossblin - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Bossblin.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event64').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event68').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Bossblin.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### BossBlob - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/BossBlob.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event6').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event19').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event12').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/BossBlob.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### Dodongo - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Dodongo.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event5').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event43').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event3').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Dodongo.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### DonPawn - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DonPawn.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event8').data.params.data['label'] = self.songs_dict['BGM_FANFARE_BOSS_HEART_GET']
            event_tools.findEvent(flow.flowchart, 'Event21').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event30').data.params.data['label'] = self.songs_dict['BGM_PANEL_RESULT']
            event_tools.findEvent(flow.flowchart, 'Event38').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
            event_tools.findEvent(flow.flowchart, 'Event6').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DonPawn.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### Gohma - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Gohma.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event0').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event1').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Gohma.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### Hinox - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Hinox.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event37').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event55').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event1').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Hinox.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### HiploopHover - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/HiploopHover.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event38').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event7').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/HiploopHover.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### Jacky - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Jacky.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event37').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event6').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Jacky.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### MightPunch - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MightPunch.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event56').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event6').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MightPunch.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        ### PiccoloMaster - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/PiccoloMaster.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event48').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event53').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event3').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/PiccoloMaster.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ### Rola - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Rola.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event20').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event1').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Rola.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        ### Shadow - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Shadow.bfevfl')
            # event_tools.findEvent(flow.flowchart, 'Event6').data.params.data['label'] = self.songs_dict['BGM_LASTBOSS_DEMO_TEXT']
            event_tools.findEvent(flow.flowchart, 'Event37').data.params.data['label'] = self.songs_dict['BGM_LASTBOSS_WIN']
            event_tools.findEvent(flow.flowchart, 'Event60').data.params.data['label'] = self.songs_dict['BGM_LASTBOSS_BATTLE']
            event_tools.findEvent(flow.flowchart, 'Event71').data.params.data['label'] = self.songs_dict['BGM_LASTBOSS_BATTLE']
            # event_tools.findEvent(flow.flowchart, 'Event44').data.params.data['label'] = self.songs_dict['BGM_LASTBOSS_DEMO_TEXT'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Shadow.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        ### StoneHinox - shuffles boss BGMs
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/StoneHinox.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event4').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event35').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE']
            event_tools.findEvent(flow.flowchart, 'Event29').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS_MIDDLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/StoneHinox.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        ### ToolShopkeeper - shuffles music when the ToolShopkeeper kills you after stealing
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ToolShopkeeper.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event87').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_BOSS']
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ToolShopkeeper.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        ### TurtleRock - shuffles Turtle Rock battle music
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/TurtleRock.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event1').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_LV8_ENT_BATTLE']
            event_tools.findEvent(flow.flowchart, 'Event26').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_LV8_ENT_BATTLE']
            event_tools.findEvent(flow.flowchart, 'Event11').data.params.data['label'] = self.songs_dict['BGM_DUNGEON_LV8_ENT_BATTLE'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/TurtleRock.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        ### WindFish - shuffles ending music
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/WindFish.bfevfl')
            event_tools.findEvent(flow.flowchart, 'Event73').data.params.data['label'] = self.songs_dict['BGM_DEMO_AFTER_LASTBOSS']
            # event_tools.findEvent(flow.flowchart, 'Event101').data.params.data['label'] = self.songs_dict['BGM_DEMO_AFTER_LASTBOSS_WIND_FISH']
            event_tools.findEvent(flow.flowchart, 'Event74').data.params.data['label'] = self.songs_dict['BGM_DEMO_AFTER_LASTBOSS'] # StopBGM
            event_tools.findEvent(flow.flowchart, 'Event93').data.params.data['label'] = self.songs_dict['BGM_LASTBOSS_WIN'] # StopBGM
            # event_tools.findEvent(flow.flowchart, 'Event118').data.params.data['label'] = self.songs_dict['BGM_DEMO_AFTER_LASTBOSS_WIND_FISH'] # StopBGM
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/WindFish.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def makeGeneralARCChanges(self):
        """Replaces the Title Screen logo with the Randomizer logo"""

        try:
            writer = oead_tools.makeSarcWriterFromSarc(f'{self.rom_path}/region_common/ui/StartUp.arc')
            
            with open(os.path.join(RESOURCE_PATH, '__Combined.bntx'), 'rb') as f: # will eventually manually replace the texture
                writer.files['timg/__Combined.bntx'] = f.read()

            if not os.path.exists(f'{self.out_dir}/Romfs/region_common/ui'):
                os.makedirs(f'{self.out_dir}/Romfs/region_common/ui')

            oead_tools.writeSarc(writer, f'{self.out_dir}/Romfs/region_common/ui/StartUp.arc')
        
        finally: # regardless if the user had the file or not, just consider this task done, the logo is not needed to play
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def makeInstrumentChanges(self):
        """Iterates through the Instrument rooms and edits the Instrument actor data"""

        # Open up the already modded SinkingSword eventflow to make new events
        flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl')
        
        for room in data.INSTRUMENT_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', data.INSTRUMENT_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                
                with open(f'{self.rom_path}/region_common/level/{dirname}/{data.INSTRUMENT_ROOMS[room]}.leb', 'rb') as roomfile:
                    room_data = leb.Room(roomfile.read())
                
                item = self.placements[room]
                item_key = self.item_defs[item]['item-key']
                item_index = self.placements['indexes'][room] if room in self.placements['indexes'] else -1

                if item_key[-4:] != 'Trap':
                    model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
                    model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
                else:
                    trap_models = copy.deepcopy(data.ITEM_MODELS)
                    
                    for i in self.placements['starting-items']:
                        i = self.item_defs[i]['item-key']
                        if i == 'SwordLv1':
                            i = 'SinkingSword'
                        if i in ['SinkingSword', 'Shield', 'PowerBraceletLv1']:
                            if self.placements['starting-items'].count(i) < 2:
                                continue
                        if i in trap_models:
                            del trap_models[i]
                    
                    if not self.placements['settings']['shuffle-instruments']:
                        for inst in self.instruments:
                            if inst in trap_models:
                                del trap_models[inst]
                    
                    model_name = random.choice(list(trap_models))
                    model_path = trap_models[model_name]
                
                if self.placements['settings']['shuffled-dungeons']:
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
                
                instruments.changeInstrument(flow.flowchart, item_key, item_index, model_path, model_name, room, room_data, destination)
                
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.INSTRUMENT_ROOMS[room]}.leb', 'wb') as outFile:
                        outFile.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)



    def makeHeartPieceChanges(self):
        """Iterates through the nonsunken Heart Piece rooms and edits the Heart Piece actor data"""

        # Open up the already modded SinkingSword eventflow to make new events
        flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl')
        
        sunken = [
            'taltal-east-drop',
            'south-bay-sunken',
            'bay-passage-sunken',
            'river-crossing-cave',
            'kanalet-moat-south'
        ]
        non_sunken = (x for x in data.HEART_ROOMS if x not in sunken)
        
        for room in non_sunken:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', data.HEART_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.HEART_ROOMS[room]}.leb'):
                    path = self.rom_path
                else:
                    path = f'{self.out_dir}/Romfs'
                
                # if data.HEART_ROOMS[room] in data.CHEST_ROOMS.values():
                #     path = f'{self.out_dir}/Romfs'
                # else:
                #     path = self.rom_path
                
                with open(f'{path}/region_common/level/{dirname}/{data.HEART_ROOMS[room]}.leb', 'rb') as roomfile:
                    room_data = leb.Room(roomfile.read())
                
                item = self.placements[room]
                item_key = self.item_defs[item]['item-key']
                item_index = self.placements['indexes'][room] if room in self.placements['indexes'] else -1

                if item_key[-4:] != 'Trap':
                    model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
                    model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
                else:
                    trap_models = copy.deepcopy(data.ITEM_MODELS)

                    for i in self.placements['starting-items']:
                        i = self.item_defs[i]['item-key']
                        if i == 'SwordLv1':
                            i = 'SinkingSword'
                        if i in ['SinkingSword', 'Shield', 'PowerBraceletLv1']:
                            if self.placements['starting-items'].count(i) < 2:
                                continue
                        if i in trap_models:
                            del trap_models[i]
                    
                    if not self.placements['settings']['shuffle-instruments']:
                        for inst in self.instruments:
                            if inst in trap_models:
                                del trap_models[inst]

                    model_name = random.choice(list(trap_models))
                    model_path = trap_models[model_name]
                
                heart_pieces.changeHeartPiece(flow.flowchart, item_key, item_index, model_path, model_name, room, room_data)
                                
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.HEART_ROOMS[room]}.leb', 'wb') as outFile:
                        outFile.write(room_data.repack())

                        if data.HEART_ROOMS[room] not in data.CHEST_ROOMS.values():
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)
            else: break
        
        # save event file
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def makeTelephoneChanges(self):
        """Edits the telephone event file to allow the player to freely swap tunics
        
        Also adds rooster and bowwow to be able to get them back if companion shuffle is on"""

        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Telephone.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        tunic_swap.writeSwapEvents(flow.flowchart)
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Telephone.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        # if self.placements['settings']['shuffle-companions']:
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
        #         if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{tel}'):
        #             os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{tel}')

        #         with open(f'{self.rom_path}/region_common/level/{tel}/{tel}_01A.leb', 'rb') as file:
        #             room_data = leb.Room(file.read())
                
        #         room_data.addTelephoneRooster(e)

        #         if self.thread_active:
        #             with open(f'{self.out_dir}/Romfs/region_common/level/{tel}/{tel}_01A.leb', 'wb') as file:
        #                 file.write(room_data.repack())
        #                 self.progress_value += 1 # update progress bar
        #                 self.progress_update.emit(self.progress_value)
            
        #     flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl')

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
        #         event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)
    


    def makeLv10RupeeChanges(self):
        """Edits the room data for the 28 free standing rupees in Color Dungeon so they are randomized"""

        from Randomizers import rupees

        flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl')

        with open(f'{self.rom_path}/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_08D.leb', 'rb') as file:
            room_data = leb.Room(file.read())
        
        trap_models = data.ITEM_MODELS.copy()
        trap_models.update({
            'SmallKey': 'ItemSmallKey.bfres',
            'NightmareKey': 'ItemNightmareKey.bfres',
            'StoneBeak': 'ItemStoneBeak.bfres',
            'Compass': 'ItemCompass.bfres',
            'DungeonMap': 'ItemDungeonMap.bfres'
        })
        
        for i in self.placements['starting-items']:
            i = self.item_defs[i]['item-key']
            if i == 'SwordLv1':
                i = 'SinkingSword'
            if i in ['SinkingSword', 'Shield', 'PowerBraceletLv1']:
                if self.placements['starting-items'].count(i) < 2:
                    continue
            if i in trap_models:
                del trap_models[i]
        
        if not self.placements['settings']['shuffle-instruments']:
            for inst in self.instruments:
                if inst in trap_models:
                    del trap_models[inst]

        for i in range(28):
            if self.thread_active:
                item = self.placements[f'D0-rupee-{i + 1}']
                item_key = self.item_defs[item]['item-key']
                item_index = self.placements['indexes'][f'D0-rupee-{i + 1}'] if f'D0-rupee-{i + 1}' in self.placements['indexes'] else -1

                if item_key[-4:] != 'Trap':
                    model_path = 'ObjSinkingSword.bfres' if item_key == 'SwordLv1' else self.item_defs[item]['model-path']
                    model_name = 'SinkingSword' if item_key == 'SwordLv1' else self.item_defs[item]['model-name']
                else:
                    model_name = random.choice(list(trap_models))
                    model_path = trap_models[model_name]

                room_data.setRupeeParams(model_path, model_name, f'Lv10Rupee_{i + 1}', item_key, i)
                rupees.makeEventChanges(flow.flowchart, i, item_key, item_index)
            else: break
        
        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_08D.leb', 'wb') as file:
                file.write(room_data.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)



    # def makeShopChanges(self):
    #     """Edits the ToolShopKeeper event file and the shop items datasheet"""

    #     flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ToolShopkeeper.bfevfl')
    #     actors.addNeededActors(flow.flowchart, self.rom_path)
    #     shop.makeEventChanges(flow.flowchart, self.placements, self.item_defs)

    #     if self.thread_active:
    #         event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ToolShopkeeper.bfevfl', flow)
    #         self.progress_value += 1 # update progress bar
    #         self.progress_update.emit(self.progress_value)
        
    #     ### ShopItem datasheet
    #     sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/ShopItem.gsheet')
    #     shop.makeDatasheetChanges(sheet, self.placements, self.item_defs)

    #     if self.thread_active:
    #         oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/ShopItem.gsheet', sheet)
    #         self.progress_value += 1 # update progress bar
    #         self.progress_update.emit(self.progress_value)



    def makeTradeQuestChanges(self):
        """Edits various event files for the Trade Quest NPCs to give the randomized items"""

        ### QuadrupletsMother
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/QuadrupletsMother.bfevfl')
            trade_quest.mamashaChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/QuadrupletsMother.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ### CiaoCiao
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/RibbonBowWow.bfevfl')
            trade_quest.ciaociaoChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/RibbonBowWow.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ### Sale
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Sale.bfevfl')
            trade_quest.saleChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Sale.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ### Kiki
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Kiki.bfevfl')
            trade_quest.kikiChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)

            # shuffle bridge building music
            if self.placements['settings']['randomize-music']:
                event_tools.findEvent(flow.flowchart, 'Event114').data.params.data['label'] = self.songs_dict['BGM_EVENT_MONKEY']
            
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Kiki.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### Tarin Bees
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/Tarin.bfevfl')
            trade_quest.tarinChanges(flow.flowchart, self.placements, self.item_defs)

            # # shuffle bees music
            # if self.placements['settings']['randomize-music']:
            #     event_tools.findEvent(flow.flowchart, 'Event113').data.params.data['label'] = self.songs_dict['BGM_EVENT_BEE']
            
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Tarin.bfevfl', flow)
        
        ### Chef Bear
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ChefBear.bfevfl')
            trade_quest.chefChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ChefBear.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### Papahl
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Papahl.bfevfl')
            trade_quest.papahlChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Papahl.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### Christine
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/Christine.bfevfl')
            trade_quest.christineChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Christine.bfevfl', flow)

        ### Mr Write
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DrWrite.bfevfl')
            trade_quest.mrWriteChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DrWrite.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### Grandma Yahoo
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/GrandmaUlrira.bfevfl')
            trade_quest.grandmaYahooChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/GrandmaUlrira.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### Bay Fisherman
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MarthasBayFisherman.bfevfl')
            trade_quest.fishermanChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MarthasBayFisherman.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### Mermaid Martha
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MermaidMartha.bfevfl')
            trade_quest.mermaidChanges(flow.flowchart, self.placements, self.item_defs, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MermaidMartha.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        # Mermaid Statue
        if self.thread_active:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MarthaStatue.bfevfl')
            trade_quest.statueChanges(flow.flowchart, self.rom_path)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MarthaStatue.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
    


    def makeOwlStatueChanges(self):
        '''Edits the eventflows for the owl statues to give items, as well as one extra level file'''

        if self.thread_active: # put the slime key check on the owl for now
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/FieldOwlStatue.bfevfl')
            actors.addNeededActors(flow.flowchart, self.rom_path)
            owls.addSlimeKeyCheck(flow.flowchart)

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/FieldOwlStatue.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        if self.thread_active and self.placements['settings']['owl-overworld-gifts']:
            owls.makeFieldChanges(flow.flowchart, self.placements, self.item_defs)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/FieldOwlStatue.bfevfl', flow)
            
        if self.thread_active and self.placements['settings']['owl-dungeon-gifts']:
            flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DungeonOwlStatue.bfevfl')
            actors.addNeededActors(flow.flowchart, self.rom_path)
            owls.makeDungeonChanges(flow.flowchart, self.placements, self.item_defs)
            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DungeonOwlStatue.bfevfl', flow)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
            
            if self.thread_active:
                with open(f'{self.rom_path}/region_common/level/Lv01TailCave/Lv01TailCave_04B.leb', 'rb') as f:
                    room_data = leb.Room(f.read())
                room_data.actors[0].parameters[0] = bytes('examine_Tail04B', 'utf-8')
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/Lv01TailCave/Lv01TailCave_04B.leb', 'wb') as f:
                        f.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
            
            if self.thread_active:
                with open(f'{self.rom_path}/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_06C.leb', 'rb') as f:
                    room_data = leb.Room(f.read())
                room_data.actors[9].parameters[0] = bytes('examine_Color06C', 'utf-8')
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_06C.leb', 'wb') as f:
                        f.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_07D.leb', 'rb') as f:
                    room_data = leb.Room(f.read())
                room_data.actors[4].parameters[0] = bytes('examine_Color07D', 'utf-8')
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_07D.leb', 'wb') as f:
                        f.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)

            if self.thread_active:
                with open(f'{self.out_dir}/Romfs/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_05F.leb', 'rb') as f:
                    room_data = leb.Room(f.read())
                room_data.actors[4].parameters[0] = bytes('examine_Color05F', 'utf-8')
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_05F.leb', 'wb') as f:
                        f.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
    


    # def makeItemModelFixes(self):
    #     """Adds necessary model files needed for various different fixes"""

    #     if not os.path.exists(f'{self.out_dir}/Romfs/region_common/actor'):
    #         os.makedirs(f'{self.out_dir}/Romfs/region_common/actor')

    #     # files = os.listdir(MODELS_PATH)

    #     # for file in files:
    #     #     model = file[:-len(data.MODELS_SUFFIX)] # Switched from Python 3.10 to 3.8, so cant use str.removesuffix lol
    #     #     if model in data.CUSTOM_MODELS:
    #     #         shutil.copy(os.path.join(MODELS_PATH, file), f'{self.out_dir}/Romfs/region_common/actor/{file}')
    #     #         self.progress_value += 1 # update progress bar
    #     #         self.progress_update.emit(self.progress_value)
        
    #     if self.thread_active:
    #         crane_prizes.makePrizeModels(self.rom_path, self.out_dir, self.placements, self.item_defs)
    #         self.progress_value += 1 # update progress bar
    #         self.progress_update.emit(self.progress_value)  



    def randomizeEnemies(self):
        """Randomizes enemy actors that do not affect logic
        Needed kills are left vanilla and potentially problematic enemies are excluded"""

        from Randomizers import enemies
        from randomizer_data import ENEMY_DATA

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
        # enemy_ids = (*land_ids, *air_ids, *water_ids, *water2D_ids, *water_shallow_ids, *tree_ids, *hole_ids)
        no_vire = list(air_ids[:])
        no_vire.remove(0x26)
        restrictions = (-1, 0x3, 0x15, 0x16, 0x3D)

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

        levels_path = f'{self.rom_path}/region_common/level'
        out_levels = f'{self.out_dir}/Romfs/region_common/level'

        included_folders = ENEMY_DATA['Included_Folders']
        # if not self.placements['settings']['panel-enemies']:
        #     included_folders = [s for s in included_folders if not s.startswith('Panel')]
        
        folders = [f for f in os.listdir(levels_path) if f in included_folders]
        
        num_of_mods = 0
        random.seed(self.seed) # restart the rng so that enemies will be the same regardless of settings

        for folder in folders:
            if self.thread_active:
                files = [f for f in os.listdir(f'{levels_path}/{folder}') if f.endswith('.leb')]

                for file in files:
                    if self.thread_active:
                        # get the path of the room file from either the romfs or the output if one has already been made
                        if not os.path.exists(f'{out_levels}/{folder}/{file}'):
                            with open(f'{levels_path}/{folder}/{file}', 'rb') as f:
                                room_data = leb.Room(f.read())
                        else:
                            with open(f'{out_levels}/{folder}/{file}', 'rb') as f:
                                room_data = leb.Room(f.read())
                        
                        rand_state, edited_room =\
                            enemies.shuffleEnemyActors(room_data, folder, file, enemy_ids, random.getstate())
                        
                        random.setstate(rand_state)

                        if edited_room:
                            if not os.path.exists(f'{out_levels}/{folder}'):
                                os.makedirs(f'{out_levels}/{folder}')
                            
                            if self.thread_active:
                                with open(f'{out_levels}/{folder}/{file}', 'wb') as f:
                                    f.write(room_data.repack())
                                    self.progress_value += 1 # update progress bar
                                    self.progress_update.emit(self.progress_value)
                                    num_of_mods += 1
                    
                    else: break
            
            else: break
        
        # print(num_of_mods)
    


    def shuffleDungeons(self):
        """Shuffles the entrances of each dungeon"""

        levels_path = f'{self.rom_path}/region_common/level'
        out_levels = f'{self.out_dir}/Romfs/region_common/level'
        ent_keys = list(self.placements['dungeon-entrances'].keys())
        ent_values = list(self.placements['dungeon-entrances'].values())

        for k,v in data.DUNGEON_ENTRANCES.items():

            ### dungeon in
            if self.thread_active:
                folder = re.match('(.+)_\\d\\d[A-Z]', v[2]).group(1)
                file = v[2]

                if not os.path.exists(f'{out_levels}/{folder}/{file}.leb'):
                    with open(f'{levels_path}/{folder}/{file}.leb', 'rb') as f:
                        room_data = leb.Room(f.read())
                else:
                    with open(f'{out_levels}/{folder}/{file}.leb', 'rb') as f:
                        room_data = leb.Room(f.read())
                
                if not os.path.exists(f'{out_levels}/{folder}'):
                    os.makedirs(f'{out_levels}/{folder}')
                
                d = data.DUNGEON_ENTRANCES[self.placements['dungeon-entrances'][k]]
                destin = d[0] + d[1]
                room_data.setLoadingZoneTarget(destin, v[4])

                if self.thread_active:
                    with open(f'{out_levels}/{folder}/{file}.leb', 'wb') as f:
                        f.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
            
            ### dungeon out
            if self.thread_active:
                folder = re.match('(.+)_\\d\\d[A-Z]', v[0]).group(1)

                if not os.path.exists(f'{out_levels}/{folder}/{v[0]}.leb'):
                    with open(f'{levels_path}/{folder}/{v[0]}.leb', 'rb') as f:
                        room_data = leb.Room(f.read())
                else:
                    with open(f'{out_levels}/{folder}/{v[0]}.leb', 'rb') as f:
                        room_data = leb.Room(f.read())
                
                if not os.path.exists(f'{out_levels}/{folder}'):
                    os.makedirs(f'{out_levels}/{folder}')
                
                d = data.DUNGEON_ENTRANCES[ent_keys[ent_values.index(k)]]
                destin = d[2] + d[3]
                room_data.setLoadingZoneTarget(destin, 0)

                if self.thread_active:
                    with open(f'{out_levels}/{folder}/{v[0]}.leb', 'wb') as f:
                        f.write(room_data.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
            
            else: break



    def shuffleDungeonIcons(self):
        ### UiFieldMapIcons datasheet: shuffle the dungeon icons so that players can use the map to track dungeon entrances
        if self.thread_active:
            icon_keys = list(data.DUNGEON_MAP_ICONS.keys())
            icon_values = list(data.DUNGEON_MAP_ICONS.values())
            maps = [i[0] for i in icon_values]
            sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/UiFieldMapIcons.gsheet')
            for icon in sheet['values']:
                if icon['mNameLabel'] in maps:
                    k = icon_keys[maps.index(icon['mNameLabel'])]
                    new_k = self.placements['dungeon-entrances'][k]
                    icon['mNameLabel'] = data.DUNGEON_MAP_ICONS[new_k][0]
                    icon['mFirstShowFlagName'] = data.DUNGEON_MAP_ICONS[new_k][1]

            if self.thread_active:
                oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/UiFieldMapIcons.gsheet', sheet)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)



    def changeLevelConfigs(self):
        '''Edits the config of the lvb files for dungeons to allow companions'''

        levels_path = f'{self.rom_path}/region_common/level'
        out_levels = f'{self.out_dir}/Romfs/region_common/level'

        # prevent companions inside the Egg since they can block Nightmare and cause a softlock easily
        folders = [f for f in os.listdir(levels_path) if f.startswith('Lv') and not f.startswith('Lv09')]

        for folder in folders:
            if self.thread_active:
                if not os.path.exists(f'{out_levels}/{folder}/{folder}.lvb'):
                    with open(f'{levels_path}/{folder}/{folder}.lvb', 'rb') as f:
                        level_data = f.read()
                        level = leb.Level(level_data)
                else:
                    with open(f'{out_levels}/{folder}/{folder}.lvb', 'rb') as f:
                        level_data = f.read()
                        level = leb.Level(level_data)
                
                level.config.attr_2 = 1 # set the companion flag to True

                if not os.path.exists(f'{out_levels}/{folder}'):
                    os.makedirs(f'{out_levels}/{folder}')
                
                with open(f'{out_levels}/{folder}/{folder}.lvb', 'wb') as f:
                    f.write(level_data.replace(level.config.data, level.config.pack())) # replaces the data and writes it to the file
                    self.progress_value += 1
                    self.progress_update.emit(self.progress_value)
            
            else: break
    


    def makeExefsPatches(self):
        """Creates the necessary exefs_patches for the Randomizer to work correctly"""

        # initialize the patcher object and hand off jobs to separate functions for easier tracking
        patcher = Patcher()
        patches.changeVanillaBehavior(patcher)
        # if self.placements['settings']['randomize-music'] and self.thread_active:
        #     patches.makeMusicPatches(patcher)
        
        # create and write in binary to an ips file with the build id of version as the name
        if self.thread_active:
            if not os.path.exists(f'{self.out_dir}/exefs_patches/las_randomizer'):
                os.makedirs(f'{self.out_dir}/exefs_patches/las_randomizer')
            
            with open(f'{self.out_dir}/exefs_patches/las_randomizer/{data.BASE_BUILD_ID}.ips', 'wb') as f:
                f.write(patcher.generatePatch())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
            
            with open(f'{self.out_dir}/exefs_patches/las_randomizer/{data.UPD_BUILD_ID}.ips', 'wb') as f:
                f.write(patcher.generatePatch())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
    


    # def fixWaterLoadingZones(self):
    #     """Changes each water loading zone to be deactivated until the player has flippers"""

    #     for room in data.WATER_LOADING_ZONES:
    #         if self.thread_active:
    #             if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/Field/{room}.leb'):
    #                 with open(f'{self.rom_path}/region_common/level/Field/{room}.leb', 'rb') as f:
    #                     room_data = leb.Room(f.read())
    #             else:
    #                 with open(f'{self.out_dir}/Romfs/region_common/level/Field/{room}.leb', 'rb') as f:
    #                     room_data = leb.Room(f.read())
                
    #             for actor in data.WATER_LOADING_ZONES[room]:
    #                 room_data.actors[actor].switches[0] = (1, self.global_flags['FlippersFound'])
                
    #             if self.thread_active:
    #                 with open(f'{self.out_dir}/Romfs/region_common/level/Field/{room}.leb', 'wb') as f:
    #                     f.write(room_data.repack())
    #                     self.progress_value += 1 # update progress bar
    #                     self.progress_update.emit(self.progress_value)
            
    #         else: break
