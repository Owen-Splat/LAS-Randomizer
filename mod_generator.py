from PySide6 import QtCore

import os
import re
import random
import shutil
import tempfile
import traceback

import Tools.leb as leb
import Tools.event_tools as event_tools
import Tools.oead_tools as oead_tools

from Randomizers import actors, chests, conditions, crane_prizes, dampe, data, flags, heart_pieces, instruments
from Randomizers import item_drops, item_get, mad_batter, marin, miscellaneous, npcs, player_start, seashell_mansion
from Randomizers import small_keys, tarin, trade_quest, tunic_swap, shop, rupees

from randomizer_paths import RESOURCE_PATH




class ModsProcess(QtCore.QThread):
    
    progress_update = QtCore.Signal(int)
    is_done = QtCore.Signal(bool)
    error = QtCore.Signal(bool)

    
    def __init__(self, placements, rom_path, out_dir, items, npcs, seed, parent=None):
        QtCore.QThread.__init__(self, parent)

        self.placements = placements
        self.rom_path = rom_path
        self.out_dir = out_dir
        self.item_defs = items
        self.new_npcs = npcs

        random.seed(seed)
        self.seed = seed

        self.progress_value = 0
        self.thread_active = True
    
    

    # STOP THREAD
    def stop(self):
        self.thread_active = False
    
    
    
    # automatically called when this thread is started
    def run(self):
        try:
            if self.thread_active: self.makeGeneralLEBChanges()
            if self.thread_active: self.makeGeneralEventChanges()
            if self.thread_active: self.makeGeneralDatasheetChanges()
            
            if self.thread_active: self.makeChestContentFixes()
            if self.thread_active: self.makeEventContentChanges()
            if self.thread_active: self.makeTradeQuestChanges()

            if self.thread_active: self.makeSmallKeyChanges()
            if self.thread_active: self.makeHeartPieceChanges()
            # if self.thread_active: self.makeShopChanges()
            
            if self.thread_active: self.makeTelephoneChanges()

            if self.thread_active: self.makeGeneralARCChanges()
            
            if self.placements['settings']['free-book'] and self.thread_active:
                self.setFreeBook()

            if self.placements['settings']['shuffle-instruments'] and self.thread_active:
                self.makeInstrumentChanges()
            
            if self.placements['settings']['blup-sanity'] and self.thread_active:
                self.makeLv10RupeeChanges()
            
            if self.placements['settings']['randomize-music'] and self.thread_active:
                self.randomizeMusic()
        
        except (FileNotFoundError, KeyError, TypeError, ValueError, IndexError):
            print(traceback.format_exc())
            self.error.emit(True)
        
        # print(self.progress_value)
        self.is_done.emit(True)
    


    # Patch LEB files of rooms with chests to update their contents
    def makeChestContentFixes(self):
        # Start by setting up the paths for the RomFS
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level')
        
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/TreasureBox.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        for room in data.CHEST_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', data.CHEST_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                
                with open(f'{self.rom_path}/region_common/level/{dirname}/{data.CHEST_ROOMS[room]}.leb', 'rb') as roomfile:
                    roomData = leb.Room(roomfile.read())

                itemKey = self.item_defs[self.placements[room]]['item-key']
                itemIndex = self.placements['indexes'][room] if room in self.placements['indexes'] else -1
                
                if room == 'taltal-5-chest-puzzle':
                    for i in range(5):
                        roomData.setChestContent(itemKey, room, i)
                else:
                    roomData.setChestContent(itemKey, room)
                
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.CHEST_ROOMS[room]}.leb', 'wb') as outfile:
                        outfile.write(roomData.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
                
                # Two special cases in D7 have duplicate rooms, once for pre-collapse and once for post-collapse. So we need to make sure we write the same data to both rooms.
                if room == 'D7-grim-creeper':
                    with open(f'{self.rom_path}/region_common/level/Lv07EagleTower/Lv07EagleTower_06H.leb', 'rb') as roomfile:
                        roomData = leb.Room(roomfile.read())

                    roomData.setChestContent(itemKey, room)
                    
                    if self.thread_active:
                        with open(f'{self.out_dir}/Romfs/region_common/level/Lv07EagleTower/Lv07EagleTower_06H.leb', 'wb') as outfile:
                            outfile.write(roomData.repack())
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)

                if room == 'D7-3f-horseheads':
                    with open(f'{self.rom_path}/region_common/level/Lv07EagleTower/Lv07EagleTower_05G.leb', 'rb') as roomfile:
                        roomData = leb.Room(roomfile.read())

                    roomData.setChestContent(itemKey, room)
                    
                    if self.thread_active:
                        with open(f'{self.out_dir}/Romfs/region_common/level/Lv07EagleTower/Lv07EagleTower_05G.leb', 'wb') as outfile:
                            outfile.write(roomData.repack())
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)

                # write the chest event
                chests.writeChestEvent(flow, room, itemKey, itemIndex)
            
            else: break
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/TreasureBox.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    # Patch SmallKey event and LEB files for rooms with small key drops to change them into other items.
    def makeSmallKeyChanges(self):
        # Start by setting up the paths for the RomFS
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level')

        # Open up the SmallKey event to be ready to edit
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/SmallKey.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        # small_keys.writeSunkenKeyEvent(flow.flowchart)

        models = data.ITEM_MODELS.copy()
        models.update({
            'SmallKey': 'ItemSmallKey.bfres',
            'NightmareKey': 'ItemNightmareKey.bfres',
            'StoneBeak': 'ItemStoneBeak.bfres',
            'Compass': 'ItemCompass.bfres',
            'DungeonMap': 'ItemDungeonMap.bfres'
        })

        for room in data.SMALL_KEY_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', data.SMALL_KEY_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')

                with open(f'{self.rom_path}/region_common/level/{dirname}/{data.SMALL_KEY_ROOMS[room]}.leb', 'rb') as roomfile:
                    roomData = leb.Room(roomfile.read())
                
                item = self.placements[room]
                itemKey = self.item_defs[item]['item-key']
                itemIndex = self.placements['indexes'][room] if room in self.placements['indexes'] else -1

                if itemKey != 'ZapTrap':
                    modelPath = self.item_defs[item]['model-path']
                    modelName = self.item_defs[item]['model-name']
                else:
                    modelName = random.choice(list(data.ITEM_MODELS))
                    modelPath = data.ITEM_MODELS[modelName]
                
                small_keys.writeKeyEvent(flow.flowchart, itemKey, itemIndex, room)
                roomData.setSmallKeyParams(modelPath, modelName, room)

                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.SMALL_KEY_ROOMS[room]}.leb', 'wb') as outfile:
                        outfile.write(roomData.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)

                if room == 'D4-sunken-item': # special case. need to write the same data in 06A
                    with open(f'{self.rom_path}/region_common/level/Lv04AnglersTunnel/Lv04AnglersTunnel_06A.leb', 'rb') as roomfile:
                        roomData = leb.Room(roomfile.read())
                
                    roomData.setSmallKeyParams(modelPath, modelName, room)
                    
                    if self.thread_active:
                        with open(f'{self.out_dir}/Romfs/region_common/level/Lv04AnglersTunnel/Lv04AnglersTunnel_06A.leb', 'wb') as outfile:
                            outfile.write(roomData.repack())
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)
            
            else: break
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SmallKey.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
    


    # Patch event flow files to change the items given by NPCs and other events
    def makeEventContentChanges(self):
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
    


    def tarinChanges(self):
        ### Event changes
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Tarin.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['tarin'] if 'tarin' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['tarin']]['item-key'], itemIndex, 'Event52', 'Event31')

        tarin.makeEventChanges(flow, self.placements)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Tarin.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def sinkingSwordChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/SinkingSword.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        # Beach
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/Field'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/Field')

        with open(f'{self.rom_path}/region_common/level/Field/Field_16C.leb', 'rb') as file:
            room = leb.Room(file.read())
        
        item = self.placements['washed-up']
        itemKey = self.item_defs[item]['item-key']
        itemIndex = self.placements['indexes']['washed-up'] if 'washed-up' in self.placements['indexes'] else -1

        if itemKey != 'ZapTrap':
            modelPath = self.item_defs[item]['model-path']
            modelName = self.item_defs[item]['model-name']
        else:
            modelName = random.choice(list(data.ITEM_MODELS))
            modelPath = data.ITEM_MODELS[modelName]
        
        miscellaneous.changeSunkenSword(flow.flowchart, itemKey, itemIndex, modelPath, modelName, room)

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
        itemKey = self.item_defs[item]['item-key']
        itemIndex = self.placements['indexes']['taltal-rooster-cave'] if 'taltal-rooster-cave' in self.placements['indexes'] else -1

        if itemKey != 'ZapTrap':
            modelPath = self.item_defs[item]['model-path']
            modelName = self.item_defs[item]['model-name']
        else:
            modelName = random.choice(list(data.ITEM_MODELS))
            modelPath = data.ITEM_MODELS[modelName]
        
        miscellaneous.changeBirdKey(flow.flowchart, itemKey, itemIndex, modelPath, modelName, room)

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
        itemKey = self.item_defs[item]['item-key']
        itemIndex = self.placements['indexes']['dream-shrine-left'] if 'dream-shrine-left' in self.placements['indexes'] else -1

        if itemKey != 'ZapTrap':
            modelPath = self.item_defs[item]['model-path']
            modelName = self.item_defs[item]['model-name']
        else:
            modelName = random.choice(list(data.ITEM_MODELS))
            modelPath = data.ITEM_MODELS[modelName]
        
        miscellaneous.changeOcarina(flow.flowchart, itemKey, itemIndex, modelPath, modelName, room)

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/DreamShrine/DreamShrine_01A.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        ##########################################################################################################################
        # Woods (mushroom)
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/Field'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/Field')

        with open(f'{self.rom_path}/region_common/level/Field/Field_06A.leb', 'rb') as file:
            room = leb.Room(file.read())
        
        item = self.placements['woods-loose']
        itemKey = self.item_defs[item]['item-key']
        itemIndex = self.placements['indexes']['woods-loose'] if 'woods-loose' in self.placements['indexes'] else -1

        if itemKey != 'ZapTrap':
            modelPath = self.item_defs[item]['model-path']
            modelName = self.item_defs[item]['model-name']
        else:
            modelName = random.choice(list(data.ITEM_MODELS))
            modelPath = data.ITEM_MODELS[modelName]
        
        miscellaneous.changeMushroom(flow.flowchart, itemKey, itemIndex, modelPath, modelName, room)

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
        itemKey = self.item_defs[item]['item-key']
        itemIndex = self.placements['indexes']['mermaid-cave'] if 'mermaid-cave' in self.placements['indexes'] else -1

        if itemKey != 'ZapTrap':
            modelPath = self.item_defs[item]['model-path']
            modelName = self.item_defs[item]['model-name']
        else:
            modelName = random.choice(list(data.ITEM_MODELS))
            modelPath = data.ITEM_MODELS[modelName]
        
        miscellaneous.changeLens(flow.flowchart, itemKey, itemIndex, modelPath, modelName, room)
        
        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/MermaidStatue/MermaidStatue_01A.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        # #########################################################################################################################
        # # Slime Key
        # if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/Field'):
        #     os.makedirs(f'{self.out_dir}/Romfs/region_common/level/Field')

        # with open(f'{self.rom_path}/region_common/level/Field/Field_13G.leb', 'rb') as file:
        #     room = leb.Room(file.read())
        
        # item = self.placements['pothole-final']
        # itemKey = self.item_defs[item]['item-key']
        # itemIndex = self.placements['indexes']['pothole-final'] if 'pothole-final' in self.placements['indexes'] else -1

        # if itemKey != 'ZapTrap':
        #     modelPath = self.item_defs[item]['model-path']
        #     modelName = self.item_defs[item]['model-name']
        # else:
        #     modelName = random.choice(data.ITEM_MODELS)
        #     modelPath = f'Item{modelName}.bfres'
        
        # miscellaneous.changeSlimeKey(flow.flowchart, itemKey, itemIndex, modelPath, modelName, room)

        # if self.thread_active:
        #     with open(f'{self.out_dir}/Romfs/region_common/level/Field/Field_13G.leb', 'wb') as file:
        #         file.write(room.repack())
        #         self.progress_value += 1 # update progress bar
        #         self.progress_update.emit(self.progress_value)

        #########################################################################################################################
        # Done!
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def walrusChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Walrus.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['walrus'] if 'walrus' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['walrus']]['item-key'], itemIndex, 'Event53', 'Event110')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Walrus.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def christineChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Christine.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['christine-grateful'] if 'christine-grateful' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['christine-grateful']]['item-key'], itemIndex, 'Event44', 'Event36')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Christine.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def invisibleZoraChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/SecretZora.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['invisible-zora'] if 'invisible-zora' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['invisible-zora']]['item-key'], itemIndex, 'Event23', 'Event27')

        event_tools.insertEventAfter(flow.flowchart, 'Event32', 'Event23')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SecretZora.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def marinChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Marin.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['marin'] if 'marin' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['marin']]['item-key'], itemIndex, 'Event246', 'Event666')

        marin.makeEventChanges(flow)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Marin.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def ghostRewardChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Owl.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        new = event_tools.createActionEvent(flow.flowchart, 'Owl', 'Destroy', {})

        itemIndex = self.placements['indexes']['ghost-reward'] if 'ghost-reward' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['ghost-reward']]['item-key'], itemIndex, 'Event34', new)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Owl.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def clothesFairyChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/FairyQueen.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D0-fairy-2'] if 'D0-fairy-2' in self.placements['indexes'] else -1
        item2 = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D0-fairy-2']]['item-key'], itemIndex, 'Event0', 'Event180')

        itemIndex = self.placements['indexes']['D0-fairy-1'] if 'D0-fairy-1' in self.placements['indexes'] else -1
        item1 = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D0-fairy-1']]['item-key'], itemIndex, 'Event0', item2)

        event_tools.insertEventAfter(flow.flowchart, 'Event128', 'Event58')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/FairyQueen.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def goriyaChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Goriya.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        flagEvent = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag', {'symbol': data.GORIYA_FLAG, 'value': True}, 'Event4')

        itemIndex = self.placements['indexes']['goriya-trader'] if 'goriya-trader' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['goriya-trader']]['item-key'], itemIndex, 'Event87', flagEvent)

        flagCheck = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.GORIYA_FLAG}, {0: 'Event7', 1: 'Event15'})
        event_tools.insertEventAfter(flow.flowchart, 'Event24', flagCheck)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Goriya.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def manboChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ManboTamegoro.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        flagEvent = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag', {'symbol': data.MANBO_FLAG, 'value': True}, 'Event13')

        itemIndex = self.placements['indexes']['manbo'] if 'manbo' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['manbo']]['item-key'], itemIndex, 'Event31', flagEvent)

        flagCheck = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.MANBO_FLAG}, {0: 'Event37', 1: 'Event35'})
        event_tools.insertEventAfter(flow.flowchart, 'Event9', flagCheck)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ManboTamegoro.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def mamuChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Mamu.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        flagEvent = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag', {'symbol': data.MAMU_FLAG, 'value': True}, 'Event40')

        itemIndex = self.placements['indexes']['mamu'] if 'mamu' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['mamu']]['item-key'], itemIndex, 'Event85', flagEvent)

        flagCheck = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': data.MAMU_FLAG}, {0: 'Event14', 1: 'Event98'})
        event_tools.insertEventAfter(flow.flowchart, 'Event10', flagCheck)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Mamu.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def rapidsChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/RaftShopMan.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['rapids-race-45'] if 'rapids-race-45' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['rapids-race-45']]['item-key'], itemIndex, 'Event42', 'Event88', canHurtPlayer=False)

        itemIndex = self.placements['indexes']['rapids-race-35'] if 'rapids-race-35' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['rapids-race-35']]['item-key'], itemIndex, 'Event40', 'Event86', canHurtPlayer=False)

        itemIndex = self.placements['indexes']['rapids-race-30'] if 'rapids-race-30' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['rapids-race-30']]['item-key'], itemIndex, 'Event38', 'Event85', canHurtPlayer=False)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/RaftShopMan.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def fishingChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Fisherman.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        changeDefs = [
            ('fishing-orange', 'Event113', 'Event212'),
            ('fishing-cheep-cheep', 'Event3', 'Event10'),
            ('fishing-ol-baron', 'Event133', 'Event140'),
            ('fishing-50', 'Event182', 'Event240'),
            ('fishing-100', 'Event191', 'Event247'),
            ('fishing-150', 'Event193', 'Event255'),
            ('fishing-loose', 'Event264', 'Event265')
        ]

        for defs in changeDefs:
            if self.thread_active:
                itemKey = self.item_defs[self.placements[defs[0]]]['item-key']
                itemIndex = self.placements['indexes'][defs[0]] if defs[0] in self.placements['indexes'] else -1
                if itemKey == 'SwordLv1':
                    event_tools.createProgressiveItemSwitch(flow.flowchart, 'SwordLv1', 'SwordLv2', data.SWORD_FOUND_FLAG, defs[1], defs[2])
                else:
                    item_get.insertItemGetAnimation(flow.flowchart, itemKey, itemIndex, defs[1], defs[2], False, False)
            else: break
        
        event_tools.insertEventAfter(flow.flowchart, 'Event20', 'Event3')
        event_tools.insertEventAfter(flow.flowchart, 'Event18', 'Event133')
        event_tools.insertEventAfter(flow.flowchart, 'Event24', 'Event191')
        event_tools.insertEventAfter(flow.flowchart, 'FishingGetBottle', 'Event264')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Fisherman.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def trendyChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/GameShopOwner.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['trendy-prize-final'] if 'trendy-prize-final' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['trendy-prize-final']]['item-key'], itemIndex, 'Event112', 'Event239')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/GameShopOwner.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def seashellMansionChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ShellMansionMaster.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['5-seashell-reward'] if '5-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event36').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['5-seashell-reward']]['item-key'], 'itemIndex': itemIndex, 'flag': 'GetSeashell10'}

        itemIndex = self.placements['indexes']['15-seashell-reward'] if '15-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event10').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['15-seashell-reward']]['item-key'], 'itemIndex': itemIndex, 'flag': 'GetSeashell20'}

        itemIndex = self.placements['indexes']['30-seashell-reward'] if '30-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event11').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['30-seashell-reward']]['item-key'], 'itemIndex': itemIndex, 'flag': 'GetSeashell30'}

        itemIndex = self.placements['indexes']['50-seashell-reward'] if '50-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event13').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['50-seashell-reward']]['item-key'], 'itemIndex': itemIndex, 'flag': 'GetSeashell50'}

        itemIndex = self.placements['indexes']['40-seashell-reward'] if '40-seashell-reward' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['40-seashell-reward']]['item-key'], itemIndex, 'Event91', 'Event79')

        seashell_mansion.makeEventChanges(flow, self.placements)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ShellMansionMaster.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def madBatterChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MadBatter.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['mad-batter-bay'] if 'mad-batter-bay' in self.placements['indexes'] else -1
        item1 = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['mad-batter-bay']]['item-key'], itemIndex, None, 'Event23')

        itemIndex = self.placements['indexes']['mad-batter-woods'] if 'mad-batter-woods' in self.placements['indexes'] else -1
        item2 = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['mad-batter-woods']]['item-key'], itemIndex, None, 'Event23')

        itemIndex = self.placements['indexes']['mad-batter-taltal'] if 'mad-batter-taltal' in self.placements['indexes'] else -1
        item3 = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['mad-batter-taltal']]['item-key'], itemIndex, None, 'Event23')

        mad_batter.writeEvents(flow, item1, item2, item3)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MadBatter.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def dampeChanges(self):
        sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/MapPieceClearReward.gsheet')

        # Page 1 reward
        dampe.makeDatasheetChanges(sheet, 3,
        self.item_defs[self.placements['dampe-page-1']]['item-key'],
        self.placements['indexes']['dampe-page-1'] if 'dampe-page-1' in self.placements['indexes'] else -1)

        # Page 2 reward
        dampe.makeDatasheetChanges(sheet, 7,
        self.item_defs[self.placements['dampe-page-2']]['item-key'],
        self.placements['indexes']['dampe-page-2'] if 'dampe-page-2' in self.placements['indexes'] else -1)

        # Final reward
        dampe.makeDatasheetChanges(sheet, 12,
        self.item_defs[self.placements['dampe-final']]['item-key'],
        self.placements['indexes']['dampe-final'] if 'dampe-final' in self.placements['indexes'] else -1)

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/MapPieceClearReward.gsheet', sheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #######

        sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/MapPieceTheme.gsheet')

        # 1-4 reward
        dampe.makeDatasheetChanges(sheet, 3,
        self.item_defs[self.placements['dampe-heart-challenge']]['item-key'],
        self.placements['indexes']['dampe-heart-challenge'] if 'dampe-heart-challenge' in self.placements['indexes'] else -1)

        # 3-2 reward
        dampe.makeDatasheetChanges(sheet, 9,
        self.item_defs[self.placements['dampe-bottle-challenge']]['item-key'],
        self.placements['indexes']['dampe-bottle-challenge'] if 'dampe-bottle-challenge' in self.placements['indexes'] else -1)

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/MapPieceTheme.gsheet', sheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def moldormChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguTail.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D1-moldorm'] if 'D1-moldorm' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D1-moldorm']]['item-key'], itemIndex, 'Event8', 'Event45')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguTail.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def genieChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/PotDemonKing.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D2-genie'] if 'D2-genie' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D2-genie']]['item-key'], itemIndex, 'Event29', 'Event56')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/PotDemonKing.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def slimeEyeChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguZol.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D3-slime-eye'] if 'D3-slime-eye' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D3-slime-eye']]['item-key'], itemIndex, 'Event29', 'Event43')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguZol.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def anglerChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Angler.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D4-angler'] if 'D4-angler' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D4-angler']]['item-key'], itemIndex, 'Event25', 'Event50')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Angler.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def slimeEelChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Hooker.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D5-slime-eel'] if 'D5-slime-eel' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D5-slime-eel']]['item-key'], itemIndex, 'Event28', 'Event13')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Hooker.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def facadeChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MatFace.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D6-facade'] if 'D6-facade' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D6-facade']]['item-key'], itemIndex, 'Event8', 'Event35')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MatFace.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def eagleChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Albatoss.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D7-eagle'] if 'D7-eagle' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D7-eagle']]['item-key'], itemIndex, 'Event40', 'Event51')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Albatoss.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def hotheadChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguFlame.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D8-hothead'] if 'D8-hothead' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D8-hothead']]['item-key'], itemIndex, 'Event13', 'Event15')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguFlame.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def lanmolaChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Lanmola.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['lanmola'] if 'lanmola' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['lanmola']]['item-key'], itemIndex, 'Event34', 'Event9')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Lanmola.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def armosKnightChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguArmos.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        event_tools.removeEventAfter(flow.flowchart, 'Event2')
        event_tools.insertEventAfter(flow.flowchart, 'Event2', 'Event8')


        itemIndex = self.placements['indexes']['armos-knight'] if 'armos-knight' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['armos-knight']]['item-key'], itemIndex, 'Event47', None)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguArmos.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def masterStalfosChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MasterStalfon.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        itemIndex = self.placements['indexes']['D5-master-stalfos'] if 'D5-master-stalfos' in self.placements['indexes'] else -1
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[self.placements['D5-master-stalfos']]['item-key'], itemIndex, 'Event37', 'Event194')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MasterStalfon.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    # Fix some LEB files in ways that are always done, regardless of self.placements.
    def makeGeneralLEBChanges(self):
        ### Entrance to Mysterious Forest: Set the owl to 0 instead of 1, prevents the cutscene from triggering in some circumstances.
        # For all other owls, setting the flags is sufficient but this one sucks.
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/Field'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/Field')

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
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell01'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell01')

        with open(f'{self.rom_path}/region_common/level/MadBattersWell01/MadBattersWell01_01A.leb', 'rb') as roomfile:
            roomData = leb.Room(roomfile.read())

        roomData.actors[2].parameters[2] = b'BatterA'

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell01/MadBattersWell01_01A.leb', 'wb') as outfile:
                outfile.write(roomData.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        # B: Woods
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell02'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell02')

        with open(f'{self.rom_path}/region_common/level/MadBattersWell02/MadBattersWell02_01A.leb', 'rb') as roomfile:
            roomData = leb.Room(roomfile.read())

        roomData.actors[6].parameters[2] = b'BatterB'

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell02/MadBattersWell02_01A.leb', 'wb') as outfile:
                outfile.write(roomData.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        # C: Mountain
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell03'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell03')

        with open(f'{self.rom_path}/region_common/level/MadBattersWell03/MadBattersWell03_01A.leb', 'rb') as roomfile:
            roomData = leb.Room(roomfile.read())

        roomData.actors[0].parameters[2] = b'BatterC'

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/MadBattersWell03/MadBattersWell03_01A.leb', 'wb') as outfile:
                outfile.write(roomData.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        ### Lanmola Cave: Remove the AnglerKey actor
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/LanmolaCave'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/LanmolaCave')

        with open(f'{self.rom_path}/region_common/level/LanmolaCave/LanmolaCave_02A.leb', 'rb') as roomfile:
            roomData = leb.Room(roomfile.read())

        roomData.actors.pop(5) # remove angler key

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/LanmolaCave/LanmolaCave_02A.leb', 'wb') as outfile:
                outfile.write(roomData.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)



    # Make changes to some events that should be in every seed, e.g. setting flags for having watched cutscenes
    def makeGeneralEventChanges(self):
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/event'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/event')

        #################################################################################################################################
        ### PlayerStart event: Sets a bunch of flags for cutscenes being watched/triggered to prevent them from ever happening.
        ### First check if FirstClear is already set, to not do the work more than once and slightly slow down loading zones.
        playerStart = event_tools.readFlow(f'{self.rom_path}/region_common/event/PlayerStart.bfevfl')
        eventFlagsActor = event_tools.findActor(playerStart.flowchart, 'EventFlags') # Store this actor for later to add it to other event flows

        player_start.makeStartChanges(playerStart, self.placements)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/PlayerStart.bfevfl', playerStart)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        # ### TreasureBox event: Adds in events to make certain items be progressive.
        treasureBox = event_tools.readFlow(f'{self.rom_path}/region_common/event/TreasureBox.bfevfl')
        flowControlActor = event_tools.findActor(treasureBox.flowchart, 'FlowControl')

        #################################################################################################################################
        ### ShellMansionPresent event: Similar to TreasureBox, must make some items progressive.
        shellPresent = event_tools.readFlow(f'{self.rom_path}/region_common/event/ShellMansionPresent.bfevfl')
        actors.addNeededActors(shellPresent.flowchart, self.rom_path)
        shellPresent.flowchart.actors.append(flowControlActor)

        seashell_mansion.changeRewards(shellPresent, treasureBox)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ShellMansionPresent.bfevfl', shellPresent)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### MusicalInstrument event: Set ghost clear flags if you got the Surf Harp.
        if not self.placements['settings']['shuffle-instruments']:
            musicalInstrument = event_tools.readFlow(f'{self.rom_path}/region_common/event/MusicalInstrument.bfevfl')

            musicalInstrument.flowchart.actors.append(eventFlagsActor)
            event_tools.addActorQuery(event_tools.findActor(musicalInstrument.flowchart, 'Inventory'), 'HasItem')

            ghostFlagsSetEvent = event_tools.createActionEvent(musicalInstrument.flowchart, 'EventFlags', 'SetFlag', {'symbol': 'GhostClear1', 'value': True})

            event_tools.insertEventAfter(musicalInstrument.flowchart, 'Event52', event_tools.createSwitchEvent(musicalInstrument.flowchart, 'Inventory', 'HasItem', {'itemType': 48, 'count': 1}, {0: 'Event0', 1: ghostFlagsSetEvent}))

            event_tools.createActionChain(musicalInstrument.flowchart, ghostFlagsSetEvent, [
                ('EventFlags', 'SetFlag', {'symbol': 'Ghost2_Clear', 'value': True}),
                ('EventFlags', 'SetFlag', {'symbol': 'Ghost3_Clear', 'value': True}),
                ('EventFlags', 'SetFlag', {'symbol': 'Ghost4_Clear', 'value': True})
                ], 'Event0')

            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MusicalInstrument.bfevfl', musicalInstrument)
        
        #################################################################################################################################
        ### Item: Add and fix some entry points for the ItemGetSequence
        item = event_tools.readFlow(f'{self.rom_path}/region_common/event/Item.bfevfl')

        """eventtools.addEntryPoint(item.flowchart, 'MagicPowder_MaxUp')
        eventtools.createActionChain(item.flowchart, 'MagicPowder_MaxUp', [
            ('Dialog', 'Show', {'message': 'Scenario:Lv1GetShield'})
            ])"""
        
        event_tools.findEntryPoint(item.flowchart, 'GreenClothes').name = 'ClothesGreen'
        event_tools.findEntryPoint(item.flowchart, 'RedClothes').name = 'ClothesRed'
        event_tools.findEntryPoint(item.flowchart, 'BlueClothes').name = 'ClothesBlue'
        event_tools.findEntryPoint(item.flowchart, 'Necklace').name = 'PinkBra'

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Item.bfevfl', item)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### MadamMeowMeow: Change her behaviour to always take back BowWow if you have him, and not do anything based on having the Horn
        madam = event_tools.readFlow(f'{self.rom_path}/region_common/event/MadamMeowMeow.bfevfl')

        # Removes BowWowClear flag being set
        event_tools.insertEventAfter(madam.flowchart, 'Event69', 'Event18')

        # Rearranging her dialogue conditions
        event_tools.insertEventAfter(madam.flowchart, 'Event22', 'Event5')
        event_tools.setSwitchEventCase(madam.flowchart, 'Event5', 0, 'Event0')
        event_tools.setSwitchEventCase(madam.flowchart, 'Event5', 1, 'Event52')
        event_tools.setSwitchEventCase(madam.flowchart, 'Event0', 0, 'Event40')
        event_tools.setSwitchEventCase(madam.flowchart, 'Event0', 1, 'Event21')
        event_tools.setSwitchEventCase(madam.flowchart, 'Event21', 0, 'Event80')
        event_tools.findEvent(madam.flowchart, 'Event21').data.params.data['symbol'] = 'BowWowJoin'

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MadamMeowMeow.bfevfl', madam)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### WindFishsEgg: Add and fix some entry points for the ItemGetSequence for capcity upgrades and tunics.
        egg = event_tools.readFlow(f'{self.rom_path}/region_common/event/WindFishsEgg.bfevfl')

        event_tools.insertEventAfter(egg.flowchart, 'Event142', None)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/WindFishsEgg.bfevfl', egg)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### SkeletalGuardBlue: Make him sell 20 bombs in addition to the 20 powder
        if self.placements['settings']['reduce-farming']:
            skeleton = event_tools.readFlow(f'{self.rom_path}/region_common/event/SkeletalGuardBlue.bfevfl')

            addBombs = event_tools.createActionEvent(skeleton.flowchart, 'Inventory', 'AddItem',
            {'itemType': 4, 'count': 20, 'autoEquip': False})

            if self.placements['settings']['shuffle-bombs']:
                checkBombs = event_tools.createSwitchEvent(skeleton.flowchart, 'EventFlags', 'CheckFlag',
                {'symbol': data.BOMBS_FOUND_FLAG}, {0: None, 1: addBombs})
                event_tools.insertEventAfter(skeleton.flowchart, 'Event19', checkBombs)
            else:
                event_tools.insertEventAfter(skeleton.flowchart, 'Event19', addBombs)

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SkeletalGuardBlue.bfevfl', skeleton)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### PrizeCommon: Change the figure to look for when the fast-trendy setting is on
        if self.placements['settings']['fast-trendy']:
            prize = event_tools.readFlow(f'{self.rom_path}/region_common/event/PrizeCommon.bfevfl')

            event_tools.findEvent(prize.flowchart, 'Event5').data.params.data['prizeType'] = 10

            if self.thread_active:
                event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/PrizeCommon.bfevfl', prize)
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        # ######################################################################################################################
        # ### Fast Songs: Skip the song learning cutscene and gives item immediately
        # if self.placements['settings']['fast-songs']:
        #     pass

        # ########################################################################################################################
        # ### Make changes to field objects
        # field = event_tools.readFlow(f'{self.rom_path}/region_common/event/FieldObject.bfevfl')
        # actors.addNeededActors(field.flowchart, self.rom_path)

        # # Give access to color dungeon even if you have a follower
        # graveOpen = event_tools.createSubFlowEvent(field.flowchart, '', 'Grave_Push', {}, None)
        # braceletCheck = event_tools.createSwitchEvent(field.flowchart, 'EventFlags', 'CheckFlag',
        # {'symbol': data.BRACELET_FOUND_FLAG}, {0: 'Event193', 1: graveOpen})
        # event_tools.insertEventAfter(field.flowchart, 'Grave_CantPush', braceletCheck)

        # # remove the events that move link to a specified spot when opening dunegons
        # event_tools.setSwitchEventCase(field.flowchart, 'Event7', 1, 'Event160')
        # event_tools.setSwitchEventCase(field.flowchart, 'Event4', 1, 'Event206')
        # event_tools.setSwitchEventCase(field.flowchart, 'Event9', 1, 'Event208')
        # event_tools.setSwitchEventCase(field.flowchart, 'Event12', 1, 'Event130')
        # event_tools.setSwitchEventCase(field.flowchart, 'Event15', 1, 'Event147')

        # if self.thread_active:
        #     event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/FieldObject.bfevfl', field)
        #     self.progress_value += 1 # update progress bar
        #     self.progress_update.emit(self.progress_value)
        
        # ########################################################################################################################
        # ### Shadow Link
        # flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ShadowLink.bfevfl')
        # actors.addNeededActors(flow.flowchart, self.rom_path)
        
        # disableEvent = event_tools.createActionChain(flow.flowchart, None, [
        #     ('ShadowLink', 'ModelVisibility', {'modelIndex': 0, 'visible': False}),
        #     ('ShadowLink', 'SetActorSwitch', {'switchIndex': 0, 'value': True})
        # ], None)
        # event_tools.insertEventAfter(flow.flowchart, 'Appear', disableEvent)

        # if self.thread_active:
        #     event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ShadowLink.bfevfl', flow)
        #     self.progress_value += 1 # update progress bar
        #     self.progress_update.emit(self.progress_value)



    # Make changes to some datasheets that are general in nature and not tied to specific item self.placements.
    def makeGeneralDatasheetChanges(self):
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/datasheets'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/datasheets')

        #################################################################################################################################
        ### Npc datasheet: Change MadBatter to use actor parameter $2 as its event entry point.
        ### Also change ItemSmallKey and ObjSinkingSword to use custom models/entry points.
        ### Change ItemClothesGreen to have the small key model, which we'll kinda hack in the Items datasheet so small keys are visible 
        ### in the GenericItemGetSequence
        ### same thing with ItemClothesRed for heart pieces
        ### Make Papahl appear in the mountains after trading for the pineapple instead of the getting the Bell
        npcSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/Npc.gsheet')

        if self.thread_active:
            npcs.makeNpcChanges(npcSheet, self.placements)
                
        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/Npc.gsheet', npcSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### ItemDrop datasheet: remove HeartContainer drops 0-7, HookShot drop, AnglerKey and FaceKey drops.
        itemDropSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/ItemDrop.gsheet')
        # item_drops.createDatasheetConditions(itemDropSheet)
        item_drops.makeDatasheetChanges(itemDropSheet, self.placements)

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/ItemDrop.gsheet', itemDropSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### Items datasheet: Set npcKeys for SmallKeys, HeartPieces, and Seashells so they show something when you get them.
        itemsSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/Items.gsheet')

        for item in itemsSheet['values']:
            if self.thread_active:
                # if item['symbol'] == 'MagicPowder_MaxUp':
                #     item['actorID'] = 124
                
                # if item['symbol'] == 'Bomb_MaxUp':
                #     item['actorID'] = 117
                
                # if item['symbol'] == 'Arrow_MaxUp':
                #     item['actorID'] = 180
                
                if item['symbol'] == 'SmallKey':
                    item['npcKey'] = 'ItemClothesGreen'
                
                if item['symbol'] == 'YoshiDoll': # this is for ocarina and instruments as they are ItemYoshiDoll actors
                    item['npcKey'] = 'ItemClothesRed'
            
            else: break
        
        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/Items.gsheet', itemsSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### Conditions datasheet
        conditionsSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/Conditions.gsheet')

        for condition in conditionsSheet['values']:
            if self.thread_active:
                conditions.editConditions(condition, self.placements)
            else: break
        
        conditions.makeConditions(conditionsSheet, self.placements)
        
        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/Conditions.gsheet', conditionsSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### CranePrize datasheet
        cranePrizeSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/CranePrize.gsheet')
        crane_prizes.makeDatasheetChanges(cranePrizeSheet)

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/CranePrize.gsheet', cranePrizeSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        #################################################################################################################################
        ### Prize Group 1
        cranePrizeSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/CranePrizeFeaturedPrizeGroup1.gsheet')
        cranePrizeSheet['values'].pop(0) # remove yoshi doll

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/CranePrizeFeaturedPrizeGroup1.gsheet', cranePrizeSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### GlobalFlags datasheet
        flagsSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/GlobalFlags.gsheet')
        flags.makeFlags(flagsSheet)

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/GlobalFlags.gsheet', flagsSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        # #################################################################################################################################
        # ### ShopItem datasheet
        # shopSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/ShopItem.gsheet')
        # shop.makeDatasheetChanges(shopSheet, self.placements, self.item_defs)

        # if self.thread_active:
        #     oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/ShopItem.gsheet', shopSheet)
        #     self.progress_value += 1 # update progress bar
        #     self.progress_update.emit(self.progress_value)



    # Set the event for the book of dark secrets to reveal the egg path without having the magnifying lens
    def setFreeBook(self):
        book = event_tools.readFlow(f'{self.rom_path}/region_common/event/Book.bfevfl')

        event_tools.insertEventAfter(book.flowchart, 'Event18', 'Event73')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Book.bfevfl', book)
    


    # Randomize the music if the player chose that setting
    def randomizeMusic(self):
        source = f'{self.rom_path}/region_common/audio/stream'
        dest = f'{self.out_dir}/Romfs/region_common/audio/stream'
        files = os.listdir(source)
        new_music = data.MUSIC_FILES[:]

        if not os.path.exists(dest):
            os.makedirs(dest)
        
        for file in files:
            if self.thread_active:
                track = file.removesuffix(data.MUSIC_SUFFIX)
                if track in data.MUSIC_FILES:
                    song = random.choice(new_music)
                    new_music.remove(song)
                    shutil.copy(f'{source}\\{file}', f'{dest}\\{song}{data.MUSIC_SUFFIX}')
                    self.progress_value += 1 # update progress bar
                    self.progress_update.emit(self.progress_value)
    


    # build arc files
    def makeGeneralARCChanges(self):
        try:
            # with open(, 'rb') as arcFile:
            writer = oead_tools.makeSarcWriterFromSarc(f'{self.rom_path}/region_common/ui/StartUp.arc')
            
            with open(os.path.join(RESOURCE_PATH, '__Combined.bntx'), 'rb') as bntxFile: # will eventually manually edit the bntx file to replace the texture, library I was using was causing the game to crash
                bntxData = bntxFile.read()
            
            writer.files['timg/__Combined.bntx'] = bntxData

            if not os.path.exists(f'{self.out_dir}/Romfs/region_common/ui'):
                os.makedirs(f'{self.out_dir}/Romfs/region_common/ui')

            oead_tools.writeSarc(writer, f'{self.out_dir}/Romfs/region_common/ui/StartUp.arc')
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        except (FileNotFoundError):
            return
    


    def makeInstrumentChanges(self):
        # Open up the already modded SinkingSword eventflow to make new events
        flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl')
        
        for room in data.INSTRUMENT_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', data.INSTRUMENT_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                
                with open(f'{self.rom_path}/region_common/level/{dirname}/{data.INSTRUMENT_ROOMS[room]}.leb', 'rb') as roomfile:
                    roomData = leb.Room(roomfile.read())
                
                item = self.placements[room]
                itemKey = self.item_defs[item]['item-key']
                itemIndex = self.placements['indexes'][room] if room in self.placements['indexes'] else -1

                if itemKey != 'ZapTrap':
                    modelPath = self.item_defs[item]['model-path']
                    modelName = self.item_defs[item]['model-name']
                else:
                    modelName = random.choice(list(data.ITEM_MODELS))
                    modelPath = data.ITEM_MODELS[modelName]
                    
                instruments.changeInstrument(flow.flowchart, itemKey, itemIndex, modelPath, modelName, room, roomData)
                
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.INSTRUMENT_ROOMS[room]}.leb', 'wb') as outFile:
                        outFile.write(roomData.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)



    # heart piece rooms
    def makeHeartPieceChanges(self):
        # Open up the already modded SinkingSword eventflow to make new events
        flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl')
        
        for room in data.HEART_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', data.HEART_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                
                if data.HEART_ROOMS[room] in data.CHEST_ROOMS.values():
                    path = f'{self.out_dir}/Romfs'
                else:
                    path = self.rom_path
                
                with open(f'{path}/region_common/level/{dirname}/{data.HEART_ROOMS[room]}.leb', 'rb') as roomfile:
                    roomData = leb.Room(roomfile.read())
                
                item = self.placements[room]
                itemKey = self.item_defs[item]['item-key']
                itemIndex = self.placements['indexes'][room] if room in self.placements['indexes'] else -1

                if itemKey != 'ZapTrap':
                    modelPath = self.item_defs[item]['model-path']
                    modelName = self.item_defs[item]['model-name']
                else:
                    modelName = random.choice(list(data.ITEM_MODELS))
                    modelPath = data.ITEM_MODELS[modelName]
                
                heart_pieces.changeHeartPiece(flow.flowchart, itemKey, itemIndex, modelPath, modelName, room, roomData)
                                
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{data.HEART_ROOMS[room]}.leb', 'wb') as outFile:
                        outFile.write(roomData.repack())

                        if data.HEART_ROOMS[room] not in data.CHEST_ROOMS.values():
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)
        
        # save event file
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    # make telephones switch tunics
    def makeTelephoneChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Telephone.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        tunic_swap.writeSwapEvents(flow.flowchart)
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Telephone.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
    


    # shuffle color dungeon rupees
    def makeLv10RupeeChanges(self):
        flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl')

        with open(f'{self.rom_path}/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_08D.leb', 'rb') as file:
            roomData = leb.Room(file.read())
        
        for i in range(28):
            item = self.placements[f'D0-Rupee-{i + 1}']
            itemKey = self.item_defs[item]['item-key']
            itemIndex = self.placements['indexes'][f'D0-Rupee-{i + 1}'] if f'D0-Rupee-{i + 1}' in self.placements['indexes'] else -1

            if itemKey != 'ZapTrap':
                modelPath = self.item_defs[item]['model-path']
                modelName = self.item_defs[item]['model-name']
            else:
                modelName = random.choice(list(data.ITEM_MODELS))
                modelPath = data.ITEM_MODELS[modelName]

            roomData.setRupeeParams(modelPath, modelName, f'Lv10Rupee_{i + 1}', i)
            rupees.makeEventChanges(flow.flowchart, i, itemKey, itemIndex)
        
        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/Lv10ClothesDungeon/Lv10ClothesDungeon_08D.leb', 'wb') as file:
                file.write(roomData.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)



    # shuffle shop items
    def makeShopChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ToolShopkeeper.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)
        shop.makeEventChanges(flow.flowchart, self.placements, self.item_defs)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ToolShopkeeper.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    # trade quest changes
    def makeTradeQuestChanges(self):
        ### yoshi doll

        ###############################################################################################################################
        ### QuadrupletsMother
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/QuadrupletsMother.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['mamasha']
        itemIndex = self.placements['indexes']['mamasha'] if 'mamasha' in self.placements['indexes'] else -1

        trade_quest.mamashaChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event15')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/QuadrupletsMother.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        ###############################################################################################################################
        ### CiaoCiao
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/RibbonBowWow.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['ciao-ciao']
        itemIndex = self.placements['indexes']['ciao-ciao'] if 'ciao-ciao' in self.placements['indexes'] else -1

        trade_quest.ciaociaoChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event21')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/RibbonBowWow.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        ################################################################################################################################
        ### Sale
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Sale.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['sale']
        itemIndex = self.placements['indexes']['sale'] if 'sale' in self.placements['indexes'] else -1

        trade_quest.saleChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event31')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Sale.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ################################################################################################################################
        ### Kiki
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Kiki.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['kiki']
        itemIndex = self.placements['indexes']['kiki'] if 'kiki' in self.placements['indexes'] else -1

        itemGet = item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, None, 'Event102')
        trade_quest.kikiChanges(flow, itemGet)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Kiki.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ################################################################################################################################
        ### Tarin Bees
        flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/Tarin.bfevfl')
        # actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['tarin-ukuku']
        itemIndex = self.placements['indexes']['tarin-ukuku'] if 'tarin-ukuku' in self.placements['indexes'] else -1

        # trade_quest.tarinChanges(flow, itemGet)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event130', 'Event29')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Tarin.bfevfl', flow)
        
        ######################################################################################################################
        ### Chef Bear
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ChefBear.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['chef-bear']
        itemIndex = self.placements['indexes']['chef-bear'] if 'chef-bear' in self.placements['indexes'] else -1

        trade_quest.chefChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event16', None) # Event4

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ChefBear.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ######################################################################################################################
        ### Papahl
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Papahl.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['papahl']
        itemIndex = self.placements['indexes']['papahl'] if 'papahl' in self.placements['indexes'] else -1

        trade_quest.papahlChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event32', 'Event62')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Papahl.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ######################################################################################################################
        ### Christine
        flow = event_tools.readFlow(f'{self.out_dir}/Romfs/region_common/event/Christine.bfevfl')
        # actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['christine-trade']
        itemIndex = self.placements['indexes']['christine-trade'] if 'christine-trade' in self.placements['indexes'] else -1

        trade_quest.christineChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event15', 'Event22')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Christine.bfevfl', flow)

        ######################################################################################################################
        ### Mr Write
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DrWrite.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['mr-write']
        itemIndex = self.placements['indexes']['mr-write'] if 'mr-write' in self.placements['indexes'] else -1

        trade_quest.mrWriteChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event48', 'Event46')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DrWrite.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ############################################################################################################################
        ### Grandma Yahoo
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/GrandmaUlrira.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['grandma-yahoo']
        itemIndex = self.placements['indexes']['grandma-yahoo'] if 'grandma-yahoo' in self.placements['indexes'] else -1

        trade_quest.grandmaYahooChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event54', 'Event33')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/GrandmaUlrira.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #######################################################################################################################################
        ### Bay Fisherman
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MarthasBayFisherman.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['bay-fisherman']
        itemIndex = self.placements['indexes']['bay-fisherman'] if 'bay-fisherman' in self.placements['indexes'] else -1

        trade_quest.fishermanChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event28', 'Event42')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MarthasBayFisherman.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        ########################################################################################################################################
        ### Mermaid Martha
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MermaidMartha.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        item = self.placements['mermaid-martha']
        itemIndex = self.placements['indexes']['mermaid-martha'] if 'mermaid-martha' in self.placements['indexes'] else -1

        trade_quest.mermaidChanges(flow)
        item_get.insertItemGetAnimation(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event73', 'Event55')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MermaidMartha.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        #################################################################################################################################
        # Mermaid Statue
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MarthaStatue.bfevfl')
        actors.addNeededActors(flow.flowchart, self.rom_path)

        trade_quest.statueChanges(flow)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MarthaStatue.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
