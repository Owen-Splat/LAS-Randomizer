from PySide6 import QtCore

import os
import re
import random
import shutil
import tempfile

import Tools.leb as leb
import Tools.event_tools as event_tools
import Tools.oead_tools as oead_tools

import Randomizers
from Randomizers.data import *

from randomizer_paths import RESOURCE_PATH




class ModsProcess(QtCore.QThread):
    
    progress_update = QtCore.Signal(int)
    is_done = QtCore.Signal(bool)
    
    
    def __init__(self, placements, rom_path, out_dir, items, npcs, parent=None):
        QtCore.QThread.__init__(self, parent)

        self.placements = placements
        self.rom_path = rom_path
        self.out_dir = out_dir
        self.item_defs = items
        self.new_npcs = npcs
        
        self.progress_value = 0
        self.thread_active = True
    
    

    # STOP THREAD
    def stop(self):
        self.thread_active = False
    
    
    
    # automatically called when this thread is started
    def run(self):
        if self.thread_active: self.makeGeneralLEBChanges()
        if self.thread_active: self.makeGeneralEventChanges()
        if self.thread_active: self.makeGeneralDatasheetChanges()
        
        if self.thread_active: self.makeChestContentFixes()
        if self.thread_active: self.makeEventContentChanges()
        
        if self.thread_active: self.makeSmallKeyChanges()
        if self.thread_active: self.makeHeartPieceChanges()
        if self.thread_active: self.makeTelephoneChanges()

        if self.thread_active: self.makeGeneralARCChanges()
        
        if self.placements['settings']['free-book'] and self.thread_active:
            self.setFreeBook()

        if self.placements['settings']['shuffle-instruments'] and self.thread_active:
            self.makeInstrumentChanges()

        if self.placements['settings']['randomize-music'] and self.thread_active:
            self.randomizeMusic()
        
        self.is_done.emit(True)
    

    
    # Patch LEB files of rooms with chests to update their contents
    def makeChestContentFixes(self):
        # Start by setting up the paths for the RomFS
        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level')
        
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/TreasureBox.bfevfl')
        self.addNeededActors(flow.flowchart)

        for room in CHEST_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', CHEST_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                
                with open(f'{self.rom_path}/region_common/level/{dirname}/{CHEST_ROOMS[room]}.leb', 'rb') as roomfile:
                    roomData = leb.Room(roomfile.read())

                itemKey = self.item_defs[self.placements[room]]['item-key']
                itemIndex = -1
                if room in self.placements['indexes']:
                    itemIndex = self.placements['indexes'][room]
                
                if room == 'taltal-5-chest-puzzle':
                    for i in range(5):
                        roomData.setChestContent(itemKey, room, i)
                else:
                    roomData.setChestContent(itemKey, room)
                                
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{CHEST_ROOMS[room]}.leb', 'wb') as outfile:
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

                # get the item get animation
                itemGet = self.insertItemGetEvent(flow.flowchart, itemKey, itemIndex)
                Randomizers.chests.write_chest_event(flow, room, itemKey, itemGet)
            
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
        self.addNeededActors(flow.flowchart)

        for room in SMALL_KEY_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', SMALL_KEY_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')

                with open(f'{self.rom_path}/region_common/level/{dirname}/{SMALL_KEY_ROOMS[room]}.leb', 'rb') as roomfile:
                    roomData = leb.Room(roomfile.read())
                
                item = self.placements[room]
                itemIndex = self.placements['indexes'][room] if room in self.placements['indexes'] else -1

                roomData.setSmallKeyParams(self.item_defs[item]['model-path'], self.item_defs[item]['model-name'], room)

                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{SMALL_KEY_ROOMS[room]}.leb', 'wb') as outfile:
                        outfile.write(roomData.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)

                if room == 'D4-sunken-item': # special case. need to write the same data in 06A
                    with open(f'{self.rom_path}/region_common/level/Lv04AnglersTunnel/Lv04AnglersTunnel_06A.leb', 'rb') as roomfile:
                        roomData = leb.Room(roomfile.read())
                
                    roomData.setSmallKeyParams(self.item_defs[item]['model-path'], self.item_defs[item]['model-name'], room)
                    
                    if self.thread_active:
                        with open(f'{self.out_dir}/Romfs/region_common/level/Lv04AnglersTunnel/Lv04AnglersTunnel_06A.leb', 'wb') as outfile:
                            outfile.write(roomData.repack())
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)
                
                # If item is SmallKey/NightmareKey/Map/Compass/Beak/Rupee, add to inventory without any pickup animation
                if item[:3] in ['key', 'nig', 'map', 'com', 'sto', 'rup']:
                    itemEvent = event_tools.createActionChain(flow.flowchart, None, [
                        ('Inventory', 'AddItemByKey', {'itemKey': self.item_defs[item]['item-key'], 'count': 1, 'index': itemIndex, 'autoEquip': False})
                    ], None)
                else:
                    itemEvent = self.insertItemGetEvent(flow.flowchart, self.item_defs[item]['item-key'], itemIndex)
                
                Randomizers.small_keys.write_key_event(flow, room, itemEvent)
            
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
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Tarin.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['tarin'] if 'tarin' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['tarin']]['item-key'], itemIndex, 'Event52', 'Event31')

        Randomizers.tarin.make_event_changes(flow, self.placements)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Tarin.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def sinkingSwordChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/SinkingSword.bfevfl')
        self.addNeededActors(flow.flowchart)

        # Beach
        item = self.placements['washed-up']
        itemIndex = self.placements['indexes']['washed-up'] if 'washed-up' in self.placements['indexes'] else -1

        self.insertItemGetEvent(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, 'Event5', 'Event8')

        fork = event_tools.findEvent(flow.flowchart, 'Event0')
        fork.data.forks.pop(0) # remove the itemget animation event
        event_tools.findEvent(flow.flowchart, 'Event1').data.params.data['itemType'] = -1

        fork = event_tools.findEvent(flow.flowchart, 'Event8')
        fork.data.forks.pop(1) # remove the sword spin attack animation event

        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/Field'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/Field')

        with open(f'{self.rom_path}/region_common/level/Field/Field_16C.leb', 'rb') as file:
            room = leb.Room(file.read())

        # Keep the normal model if it's a sword
        room.actors[4].parameters[0] = bytes('ObjSinkingSword.bfres' if item == 'sword' else self.item_defs[item]['model-path'], 'utf-8')
        room.actors[4].parameters[1] = bytes('SinkingSword' if item == 'sword' else self.item_defs[item]['model-name'], 'utf-8')
        room.actors[4].parameters[2] = bytes('examine', 'utf-8')
        room.actors[4].parameters[3] = bytes('SwordGet', 'utf-8')

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/Field/Field_16C.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        # Rooster Cave (bird key)
        event_tools.addEntryPoint(flow.flowchart, 'TalTal')

        item = self.placements['taltal-rooster-cave']
        itemIndex = self.placements['indexes']['taltal-rooster-cave'] if 'taltal-rooster-cave' in self.placements['indexes'] else -1
        birdKeyItemGet = self.insertItemGetEvent(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, None, None)

        event_tools.createActionChain(flow.flowchart, 'TalTal', [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': ROOSTER_CAVE_FLAG, 'value': True})
            ], birdKeyItemGet)

        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/EagleKeyCave'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/EagleKeyCave')

        with open(f'{self.rom_path}/region_common/level/EagleKeyCave/EagleKeyCave_01A.leb', 'rb') as file:
            room = leb.Room(file.read())

        room.actors[0].type = 0x194
        room.actors[0].parameters[0] = bytes(self.item_defs[item]['model-path'], 'utf-8')
        room.actors[0].parameters[1] = bytes(self.item_defs[item]['model-name'], 'utf-8')
        room.actors[0].parameters[2] = bytes('TalTal', 'utf-8')
        room.actors[0].parameters[3] = bytes(ROOSTER_CAVE_FLAG, 'utf-8')

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/EagleKeyCave/EagleKeyCave_01A.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        # Dream Shrine (ocarina)
        event_tools.addEntryPoint(flow.flowchart, 'DreamShrine')

        item = self.placements['dream-shrine-left']
        itemIndex = self.placements['indexes']['dream-shrine-left'] if 'dream-shrine-left' in self.placements['indexes'] else -1
        dreamShrineItemGet = self.insertItemGetEvent(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, None, None)

        event_tools.createActionChain(flow.flowchart, 'DreamShrine', [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': DREAM_SHRINE_FLAG, 'value': True})
            ], dreamShrineItemGet)

        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/DreamShrine'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/DreamShrine')

        with open(f'{self.rom_path}/region_common/level/DreamShrine/DreamShrine_01A.leb', 'rb') as file:
            room = leb.Room(file.read())

        room.actors[5].type = 0x194
        room.actors[5].parameters[0] = bytes(self.item_defs[item]['model-path'], 'utf-8')
        room.actors[5].parameters[1] = bytes(self.item_defs[item]['model-name'], 'utf-8')
        room.actors[5].parameters[2] = bytes('DreamShrine', 'utf-8')
        room.actors[5].parameters[3] = bytes(DREAM_SHRINE_FLAG, 'utf-8')

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/DreamShrine/DreamShrine_01A.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)

        # Woods (mushroom)
        event_tools.addEntryPoint(flow.flowchart, 'Woods')

        item = self.placements['woods-loose']
        itemIndex = self.placements['indexes']['woods-loose'] if 'woods-loose' in self.placements['indexes'] else -1
        woodsItemGet = self.insertItemGetEvent(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, None, None)

        event_tools.createActionChain(flow.flowchart, 'Woods', [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': WOODS_LOOSE_FLAG, 'value': True})
            ], woodsItemGet)

        if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/Field'):
            os.makedirs(f'{self.out_dir}/Romfs/region_common/level/Field')

        with open(f'{self.rom_path}/region_common/level/Field/Field_06A.leb', 'rb') as file:
            room = leb.Room(file.read())

        room.actors[3].type = 0x194
        room.actors[3].parameters[0] = bytes(self.item_defs[item]['model-path'], 'utf-8')
        room.actors[3].parameters[1] = bytes(self.item_defs[item]['model-name'], 'utf-8')
        room.actors[3].parameters[2] = bytes('Woods', 'utf-8')
        room.actors[3].parameters[3] = bytes(WOODS_LOOSE_FLAG, 'utf-8')

        if self.thread_active:
            with open(f'{self.out_dir}/Romfs/region_common/level/Field/Field_06A.leb', 'wb') as file:
                file.write(room.repack())
                self.progress_value += 1 # update progress bar
                self.progress_update.emit(self.progress_value)
        
        # Done!
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def walrusChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Walrus.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['walrus'] if 'walrus' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['walrus']]['item-key'], itemIndex, 'Event53', 'Event110')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Walrus.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def christineChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Christine.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['christine-grateful'] if 'christine-grateful' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['christine-grateful']]['item-key'], itemIndex, 'Event44', 'Event36')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Christine.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def invisibleZoraChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/SecretZora.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['invisible-zora'] if 'invisible-zora' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['invisible-zora']]['item-key'], itemIndex, 'Event23', 'Event27')

        event_tools.insertEventAfter(flow.flowchart, 'Event32', 'Event23')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SecretZora.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def marinChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Marin.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['marin'] if 'marin' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['marin']]['item-key'], itemIndex, 'Event246', 'Event666')

        fork = event_tools.findEvent(flow.flowchart, 'Event249')
        fork.data.forks.pop(0)
        event_tools.insertEventAfter(flow.flowchart, 'Event27', 'Event249')
        event20 = event_tools.findEvent(flow.flowchart, 'Event20')
        event160 = event_tools.findEvent(flow.flowchart, 'Event160')
        event676 = event_tools.findEvent(flow.flowchart, 'Event676')
        event160.data.actor = event20.data.actor
        event676.data.actor = event20.data.actor
        event160.data.actor_query = event20.data.actor_query
        event676.data.actor_query = event20.data.actor_query
        event160.data.params.data['symbol'] = 'MarinsongGet'
        event676.data.params.data['symbol'] = 'MarinsongGet'

        # Make Marin not do beach_talk under any circumstance
        event_tools.setSwitchEventCase(flow.flowchart, 'Event21', 0, 'Event674')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Marin.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def ghostRewardChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Owl.bfevfl')
        self.addNeededActors(flow.flowchart)

        new = event_tools.createActionEvent(flow.flowchart, 'Owl', 'Destroy', {})

        itemIndex = self.placements['indexes']['ghost-reward'] if 'ghost-reward' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['ghost-reward']]['item-key'], itemIndex, 'Event34', new)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Owl.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def clothesFairyChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/FairyQueen.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D0-fairy-2'] if 'D0-fairy-2' in self.placements['indexes'] else -1
        item2 = self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D0-fairy-2']]['item-key'], itemIndex, 'Event0', 'Event180')

        itemIndex = self.placements['indexes']['D0-fairy-1'] if 'D0-fairy-1' in self.placements['indexes'] else -1
        item1 = self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D0-fairy-1']]['item-key'], itemIndex, 'Event0', item2)

        event_tools.insertEventAfter(flow.flowchart, 'Event128', 'Event58')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/FairyQueen.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def goriyaChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Goriya.bfevfl')
        self.addNeededActors(flow.flowchart)

        flagEvent = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag', {'symbol': GORIYA_FLAG, 'value': True}, 'Event4')

        itemIndex = self.placements['indexes']['goriya-trader'] if 'goriya-trader' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['goriya-trader']]['item-key'], itemIndex, 'Event87', flagEvent)

        flagCheck = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': GORIYA_FLAG}, {0: 'Event7', 1: 'Event15'})
        event_tools.insertEventAfter(flow.flowchart, 'Event24', flagCheck)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Goriya.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def manboChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ManboTamegoro.bfevfl')
        self.addNeededActors(flow.flowchart)

        flagEvent = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag', {'symbol': MANBO_FLAG, 'value': True}, 'Event13')

        itemIndex = self.placements['indexes']['manbo'] if 'manbo' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['manbo']]['item-key'], itemIndex, 'Event31', flagEvent)

        flagCheck = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': MANBO_FLAG}, {0: 'Event37', 1: 'Event35'})
        event_tools.insertEventAfter(flow.flowchart, 'Event9', flagCheck)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ManboTamegoro.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def mamuChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Mamu.bfevfl')
        self.addNeededActors(flow.flowchart)

        flagEvent = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag', {'symbol': MAMU_FLAG, 'value': True}, 'Event40')

        itemIndex = self.placements['indexes']['mamu'] if 'mamu' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['mamu']]['item-key'], itemIndex, 'Event85', flagEvent)

        flagCheck = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': MAMU_FLAG}, {0: 'Event14', 1: 'Event98'})
        event_tools.insertEventAfter(flow.flowchart, 'Event10', flagCheck)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Mamu.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def rapidsChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/RaftShopMan.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['rapids-race-45'] if 'rapids-race-45' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['rapids-race-45']]['item-key'], itemIndex, 'Event42', 'Event88')

        itemIndex = self.placements['indexes']['rapids-race-35'] if 'rapids-race-35' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['rapids-race-35']]['item-key'], itemIndex, 'Event40', 'Event86')

        itemIndex = self.placements['indexes']['rapids-race-30'] if 'rapids-race-30' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['rapids-race-30']]['item-key'], itemIndex, 'Event38', 'Event85')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/RaftShopMan.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def fishingChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Fisherman.bfevfl')
        self.addNeededActors(flow.flowchart)

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
                itemIndex = self.placements['indexes'][defs[0]] if defs[0] in self.placements['indexes'] else -1
                self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements[defs[0]]]['item-key'], itemIndex, defs[1], defs[2])
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
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['trendy-prize-final'] if 'trendy-prize-final' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['trendy-prize-final']]['item-key'], itemIndex, 'Event112', 'Event239')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/GameShopOwner.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def seashellMansionChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ShellMansionMaster.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['5-seashell-reward'] if '5-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event36').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['5-seashell-reward']]['item-key'], 'itemIndex': itemIndex, 'flag': 'GetSeashell10'}

        itemIndex = self.placements['indexes']['15-seashell-reward'] if '15-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event10').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['15-seashell-reward']]['item-key'], 'itemIndex': itemIndex, 'flag': 'GetSeashell20'}

        itemIndex = self.placements['indexes']['30-seashell-reward'] if '30-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event11').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['30-seashell-reward']]['item-key'], 'itemIndex': itemIndex, 'flag': 'GetSeashell30'}

        itemIndex = self.placements['indexes']['50-seashell-reward'] if '50-seashell-reward' in self.placements['indexes'] else -1
        event_tools.findEvent(flow.flowchart, 'Event13').data.params.data = {'pointIndex': 0, 'itemKey': self.item_defs[self.placements['50-seashell-reward']]['item-key'], 'itemIndex': itemIndex, 'flag': 'GetSeashell50'}

        # 40 shells, doesn't use a present box
        event_tools.findEvent(flow.flowchart, 'Event65').data.forks.pop(0)

        event_tools.insertEventAfter(flow.flowchart, 'Event64', 'Event65')

        # Remove the thing to show Link's sword because it will show L1 sword if he has none. 
        swordCheck1 = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': SWORD_FOUND_FLAG}, {0: 'Event65', 1: 'Event64'})
        event_tools.insertEventAfter(flow.flowchart, 'Event80', swordCheck1)

        # However, leave it the 2nd time if he's going to get one here.
        if self.placements['40-seashell-reward'] != 'sword':
            swordCheck2 = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': SWORD_FOUND_FLAG}, {0: 'Event48', 1: 'Event47'})
            event_tools.insertEventAfter(flow.flowchart, 'Event54', swordCheck2)

        itemIndex = self.placements['indexes']['40-seashell-reward'] if '40-seashell-reward' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['40-seashell-reward']]['item-key'], itemIndex, 'Event91', 'Event79')

        # Special case, if there is a sword here, then actually give them item before the end of the animation so it looks like the vanilla cutscene :)
        if self.placements['40-seashell-reward'] == 'sword':
            earlyGiveSword1 = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv1', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
            earlyGiveSword2 = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv2', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
            swordCheck3 = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': SWORD_FOUND_FLAG}, {0: earlyGiveSword1, 1: earlyGiveSword2})
            event_tools.insertEventAfter(flow.flowchart, 'Event74', swordCheck3)
        else:
            event_tools.insertEventAfter(flow.flowchart, 'Event74', 'Event19')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ShellMansionMaster.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def madBatterChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MadBatter.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['mad-batter-bay'] if 'mad-batter-bay' in self.placements['indexes'] else -1
        item1 = self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['mad-batter-bay']]['item-key'], itemIndex, None, 'Event23')

        itemIndex = self.placements['indexes']['mad-batter-woods'] if 'mad-batter-woods' in self.placements['indexes'] else -1
        item2 = self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['mad-batter-woods']]['item-key'], itemIndex, None, 'Event23')

        itemIndex = self.placements['indexes']['mad-batter-taltal'] if 'mad-batter-taltal' in self.placements['indexes'] else -1
        item3 = self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['mad-batter-taltal']]['item-key'], itemIndex, None, 'Event23')

        Randomizers.mad_batter.write_events(flow, item1, item2, item3)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MadBatter.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def dampeChanges(self):
        sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/MapPieceClearReward.gsheet')

        # Page 1 reward
        itemIndex = self.placements['indexes']['dampe-page-1'] if 'dampe-page-1' in self.placements['indexes'] else -1
        sheet['values'][3]['mRewardItem'] = self.item_defs[self.placements['dampe-page-1']]['item-key']
        sheet['values'][3]['mRewardItemEventEntry'] = self.item_defs[self.placements['dampe-page-1']]['item-key']
        sheet['values'][3]['mRewardItemIndex'] = itemIndex

        # Page 2 reward
        itemIndex = self.placements['indexes']['dampe-page-2'] if 'dampe-page-2' in self.placements['indexes'] else -1
        sheet['values'][7]['mRewardItem'] = self.item_defs[self.placements['dampe-page-2']]['item-key']
        sheet['values'][7]['mRewardItemEventEntry'] = self.item_defs[self.placements['dampe-page-2']]['item-key']
        sheet['values'][7]['mRewardItemIndex'] = itemIndex

        # FInal reward
        itemIndex = self.placements['indexes']['dampe-final'] if 'dampe-final' in self.placements['indexes'] else -1
        sheet['values'][12]['mRewardItem'] = self.item_defs[self.placements['dampe-final']]['item-key']
        sheet['values'][12]['mRewardItemEventEntry'] = self.item_defs[self.placements['dampe-final']]['item-key']
        sheet['values'][12]['mRewardItemIndex'] = itemIndex

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/MapPieceClearReward.gsheet', sheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #######

        sheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/MapPieceTheme.gsheet')

        # 1-4 reward
        itemIndex = self.placements['indexes']['dampe-heart-challenge'] if 'dampe-heart-challenge' in self.placements['indexes'] else -1
        sheet['values'][3]['mRewardItem'] = self.item_defs[self.placements['dampe-heart-challenge']]['item-key']
        sheet['values'][3]['mRewardItemEventEntry'] = self.item_defs[self.placements['dampe-heart-challenge']]['item-key']
        sheet['values'][3]['mRewardItemIndex'] = itemIndex

        # 3-2 reward
        itemIndex = self.placements['indexes']['dampe-bottle-challenge'] if 'dampe-bottle-challenge' in self.placements['indexes'] else -1
        sheet['values'][9]['mRewardItem'] = self.item_defs[self.placements['dampe-bottle-challenge']]['item-key']
        sheet['values'][9]['mRewardItemEventEntry'] = self.item_defs[self.placements['dampe-bottle-challenge']]['item-key']
        sheet['values'][9]['mRewardItemIndex'] = itemIndex

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/MapPieceTheme.gsheet', sheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def moldormChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguTail.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D1-moldorm'] if 'D1-moldorm' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D1-moldorm']]['item-key'], itemIndex, 'Event8', 'Event45')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguTail.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def genieChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/PotDemonKing.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D2-genie'] if 'D2-genie' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D2-genie']]['item-key'], itemIndex, 'Event29', 'Event56')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/PotDemonKing.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def slimeEyeChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguZol.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D3-slime-eye'] if 'D3-slime-eye' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D3-slime-eye']]['item-key'], itemIndex, 'Event29', 'Event43')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguZol.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def anglerChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Angler.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D4-angler'] if 'D4-angler' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D4-angler']]['item-key'], itemIndex, 'Event25', 'Event50')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Angler.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def slimeEelChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Hooker.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D5-slime-eel'] if 'D5-slime-eel' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D5-slime-eel']]['item-key'], itemIndex, 'Event28', 'Event13')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Hooker.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def facadeChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MatFace.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D6-facade'] if 'D6-facade' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D6-facade']]['item-key'], itemIndex, 'Event8', 'Event35')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/MatFace.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def eagleChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Albatoss.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D7-eagle'] if 'D7-eagle' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D7-eagle']]['item-key'], itemIndex, 'Event40', 'Event51')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Albatoss.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def hotheadChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguFlame.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D8-hothead'] if 'D8-hothead' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D8-hothead']]['item-key'], itemIndex, 'Event13', 'Event15')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguFlame.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def lanmolaChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Lanmola.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['lanmola'] if 'lanmola' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['lanmola']]['item-key'], itemIndex, 'Event34', 'Event9')

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Lanmola.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def armosKnightChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/DeguArmos.bfevfl')
        self.addNeededActors(flow.flowchart)
        event_tools.removeEventAfter(flow.flowchart, 'Event2')
        event_tools.insertEventAfter(flow.flowchart, 'Event2', 'Event8')


        itemIndex = self.placements['indexes']['armos-knight'] if 'armos-knight' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['armos-knight']]['item-key'], itemIndex, 'Event47', None)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/DeguArmos.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    def masterStalfosChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/MasterStalfon.bfevfl')
        self.addNeededActors(flow.flowchart)

        itemIndex = self.placements['indexes']['D5-master-stalfos'] if 'D5-master-stalfos' in self.placements['indexes'] else -1
        self.insertItemGetEvent(flow.flowchart, self.item_defs[self.placements['D5-master-stalfos']]['item-key'], itemIndex, 'Event37', 'Event194')

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

        Randomizers.player_start.make_start_changes(playerStart, self.placements)

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
        self.addNeededActors(shellPresent.flowchart)
        shellPresent.flowchart.actors.append(flowControlActor)

        powderCapacityGetEvent = self.insertItemGetEvent(shellPresent.flowchart, 'MagicPowder_MaxUp', -1, None, 'Event0')
        bombCapacityGetEvent = self.insertItemGetEvent(shellPresent.flowchart, 'Bomb_MaxUp', -1, None, 'Event0')
        arrowCapacityGetEvent = self.insertItemGetEvent(shellPresent.flowchart, 'Arrow_MaxUp', -1, None, 'Event0')
        redTunicGetEvent = self.insertItemGetEvent(shellPresent.flowchart, 'ClothesRed', -1, None, 'Event0')
        blueTunicGetEvent = self.insertItemGetEvent(shellPresent.flowchart, 'ClothesBlue', -1, None, 'Event0')
        harpGetEvent = self.insertItemGetEvent(shellPresent.flowchart, 'SurfHarp', -1, None, 'Event0')

        Randomizers.seashell_mansion.change_rewards(shellPresent, treasureBox, powderCapacityGetEvent, bombCapacityGetEvent,
        arrowCapacityGetEvent, redTunicGetEvent, blueTunicGetEvent, harpGetEvent)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/ShellMansionPresent.bfevfl', shellPresent)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### Item: Add and fix some entry points for the ItemGetSequence for capcity upgrades and tunics.
        item = event_tools.readFlow(f'{self.rom_path}/region_common/event/Item.bfevfl')

        """eventtools.addEntryPoint(item.flowchart, 'MagicPowder_MaxUp')
        eventtools.createActionChain(item.flowchart, 'MagicPowder_MaxUp', [
            ('Dialog', 'Show', {'message': 'Scenario:Lv1GetShield'})
            ])"""
        
        event_tools.findEntryPoint(item.flowchart, 'GreenClothes').name = 'ClothesGreen'
        event_tools.findEntryPoint(item.flowchart, 'RedClothes').name = 'ClothesRed'
        event_tools.findEntryPoint(item.flowchart, 'BlueClothes').name = 'ClothesBlue'

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
        ### SkeletalGuardBlue: Make him sell 20 bombs in addition to the 20 powder.
        if self.placements['settings']['reduce-farming']:
            skeleton = event_tools.readFlow(f'{self.rom_path}/region_common/event/SkeletalGuardBlue.bfevfl')

            event_tools.createActionChain(skeleton.flowchart, 'Event19', [
                ('Inventory', 'AddItem', {'itemType': 4, 'count': 20, 'autoEquip': False})
                ])

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

        ########################################################################################################################
        ### Give access to color dungeon even if you have a follower
        field = event_tools.readFlow(f'{self.rom_path}/region_common/event/FieldObject.bfevfl')
        
        graveOpen = event_tools.createSubFlowEvent(field.flowchart, '', 'Grave_Push', {}, None)
        braceletCheck = event_tools.createSwitchEvent(field.flowchart, 'Inventory', 'HasItem', {'count': 1, 'itemType': 14}, {0: 'Event193', 1: graveOpen})
        event_tools.insertEventAfter(field.flowchart, 'Grave_CantPush', braceletCheck)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/FieldObject.bfevfl', field)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



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

        for npc in npcSheet['values']:
            if self.thread_active:
                Randomizers.npcs.make_npc_changes(npc, self.placements)
            else: break
        
        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/Npc.gsheet', npcSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### ItemDrop datasheet: remove HeartContainer drops 0-7, HookShot drop, AnglerKey and FaceKey drops.
        itemDropSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/ItemDrop.gsheet')
        Randomizers.item_drops.make_datasheet_changes(itemDropSheet, self.placements)

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/ItemDrop.gsheet', itemDropSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### Items datasheet: Set actor IDs for the capacity upgrades so they show something when you get them.
        itemsSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/Items.gsheet')

        for item in itemsSheet['values']:
            if self.thread_active:
                if item['symbol'] == 'MagicPowder_MaxUp':
                    item['actorID'] = 124
                
                if item['symbol'] == 'Bomb_MaxUp':
                    item['actorID'] = 117
                
                if item['symbol'] == 'Arrow_MaxUp':
                    item['actorID'] = 180
                
                if item['symbol'] == 'SmallKey':
                    item['npcKey'] = 'ItemClothesGreen'
                
                # if item['symbol'] == 'HeartPiece':
                #     item['npcKey'] = 'ItemClothesRed'
            
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
                Randomizers.conditions.edit_conditions(condition, self.placements, SHIELD_FOUND_FLAG)
            else: break
        
        Randomizers.conditions.make_conditions(conditionsSheet, self.placements, SHIELD_FOUND_FLAG)
        
        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/Conditions.gsheet', conditionsSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)

        #################################################################################################################################
        ### CranePrize datasheet
        cranePrizeSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/CranePrize.gsheet')
        Randomizers.crane_prizes.make_datasheet_changes(cranePrizeSheet, SHIELD_FOUND_FLAG)

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/CranePrize.gsheet', cranePrizeSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
        
        ###########################################################################################################################
        ### GlobalFlags datasheet
        flagsSheet = oead_tools.readSheet(f'{self.rom_path}/region_common/datasheets/GlobalFlags.gsheet')
        Randomizers.flags.make_flags(flagsSheet)

        if self.thread_active:
            oead_tools.writeSheet(f'{self.out_dir}/Romfs/region_common/datasheets/GlobalFlags.gsheet', flagsSheet)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    # Ensure that the flowchart has the AddItemByKey and GenericItemGetSequenceByKey actions, and the EventFlags actor
    # with the SetFlag and CheckFlag action/query.
    def addNeededActors(self, flowchart):
        try:
            event_tools.findActor(flowchart, 'Inventory')
        except ValueError:
            inventoryActor = event_tools.findActor(event_tools.readFlow(f'{self.rom_path}/region_common/event/Tarin.bfevfl').flowchart, 'Inventory')
            flowchart.actors.append(inventoryActor)

        try:
            event_tools.findActor(flowchart, 'Inventory').find_action('AddItemByKey')
        except ValueError:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Inventory'), 'AddItemByKey')

        try:
            event_tools.findActor(flowchart, 'Link').find_action('GenericItemGetSequenceByKey')
        except ValueError:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'GenericItemGetSequenceByKey')
        
        try:
            event_tools.findActor(flowchart, 'Link').find_action('PlayTailorOtherChannelEx')
        except:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'PlayTailorOtherChannelEx')
        
        try:
            event_tools.findActor(flowchart, 'Link').find_action('Heal')
        except:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'Heal')
        
        try:
            event_tools.findActor(flowchart, 'Link').find_action('RequestSwordRolling')
        except:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'RequestSwordRolling')

        try:
            event_tools.findActor(flowchart, 'Link').find_action('PlayAnimationEx')
        except:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'PlayAnimationEx')

        try:
            event_tools.findActor(flowchart, 'EventFlags')
        except ValueError:
            eventFlagsActor = event_tools.findActor(event_tools.readFlow(f'{self.rom_path}/region_common/event/PlayerStart.bfevfl').flowchart, 'EventFlags')
            flowchart.actors.append(eventFlagsActor)

        try:
            event_tools.findActor(flowchart, 'EventFlags').find_action('SetFlag')
        except ValueError:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'EventFlags'), 'SetFlag')

        try:
            event_tools.findActor(flowchart, 'EventFlags').find_query('CheckFlag')
        except ValueError:
            event_tools.addActorQuery(event_tools.findActor(flowchart, 'EventFlags'), 'CheckFlag')
        
        # extra needed actors for instrument level jump
        try:
            event_tools.findActor(flowchart, 'Link').find_action('PlayInstrumentShineEffect')
        except ValueError:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'PlayInstrumentShineEffect')
        
        try:
            event_tools.findActor(flowchart, 'Audio')
        except ValueError:
            audioActor = event_tools.findActor(event_tools.readFlow(f'{self.rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'Audio')
            flowchart.actors.append(audioActor)

        try:
            event_tools.findActor(flowchart, 'Audio').find_action('StopOtherThanSystemSE')
        except ValueError:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Audio'), 'StopOtherThanSystemSE')

        try:
            event_tools.findActor(flowchart, 'Audio').find_action('PlayOneshotSystemSE')
        except ValueError:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Audio'), 'PlayOneshotSystemSE')

        try:
            event_tools.findActor(flowchart, 'Fade')
        except ValueError:
            fadeActor = event_tools.findActor(event_tools.readFlow(f'{self.rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'Fade')
            flowchart.actors.append(fadeActor)
        
        try:
            event_tools.findActor(flowchart, 'GameControl')
        except ValueError:
            controlActor = event_tools.findActor(event_tools.readFlow(f'{self.rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'GameControl')
            flowchart.actors.append(controlActor)
        
        try:
            event_tools.findActor(flowchart, 'Timer')
        except ValueError:
            timeActor = event_tools.findActor(event_tools.readFlow(f'{self.rom_path}/region_common/event/MusicalInstrument.bfevfl').flowchart, 'Timer')
            flowchart.actors.append(timeActor)



    # Inserts an AddItemByKey and a GenericItemGetSequenceByKey, or a progressive item switch (depending on the item).
    # It goes after 'before' and before 'after'. Return the name of the first event in the sequence.
    def insertItemGetEvent(self, flowchart, item, index, before=None, after=None):
        if item == 'PowerBraceletLv1':
            return event_tools.createProgressiveItemSwitch(flowchart, 'PowerBraceletLv1', 'PowerBraceletLv2', BRACELET_FOUND_FLAG, before, after)

        if item == 'SwordLv1':
            spinAnim = event_tools.createActionChain(flowchart, before, [
                ('Link', 'RequestSwordRolling', {}),
                ('Link', 'PlayAnimationEx', {'blendTime': 0.1, 'name': 'slash_hold_lp', 'time': 0.8})
            ], after)
            return event_tools.createProgressiveItemSwitch(flowchart, 'SwordLv1', 'SwordLv2', SWORD_FOUND_FLAG, before, spinAnim)

        if item == 'Shield':
            return event_tools.createProgressiveItemSwitch(flowchart, 'Shield', 'MirrorShield', SHIELD_FOUND_FLAG, before, after)

        if item == 'MagicPowder_MaxUp':
            return event_tools.createActionChain(flowchart, before, [
                ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
                ('Inventory', 'AddItemByKey', {'itemKey': 'MagicPowder', 'count': 40, 'index': -1, 'autoEquip': False}),
                ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder', 'keepCarry': False, 'messageEntry': ''})
                ], after)

        if item == 'Bomb_MaxUp':
            return event_tools.createActionChain(flowchart, before, [
                ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
                ('Inventory', 'AddItemByKey', {'itemKey': 'Bomb', 'count': 60, 'index': -1, 'autoEquip': False}),
                ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'Bomb', 'keepCarry': False, 'messageEntry': ''})
                ], after)

        if item == 'Arrow_MaxUp':
            return event_tools.createActionChain(flowchart, before, [
                ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
                ('Inventory', 'AddItemByKey', {'itemKey': 'Arrow', 'count': 60, 'index': -1, 'autoEquip': False}),
                ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'Arrow', 'keepCarry': False, 'messageEntry': ''})
                ], after)
        
        if item == 'SurfHarp':
            return event_tools.createActionChain(flowchart, before, [
                ('EventFlags', 'SetFlag', {'symbol': 'GhostClear1', 'value': True}), # set flags before giving harp, otherwise ghost requirements may be met during the itemget animation, leaving the player with a ghost that can only be rid of by getting another follower
                ('EventFlags', 'SetFlag', {'symbol': 'Ghost2_Clear', 'value': True}),
                ('EventFlags', 'SetFlag', {'symbol': 'Ghost3_Clear', 'value': True}),
                ('EventFlags', 'SetFlag', {'symbol': 'Ghost4_Clear', 'value': True}),
                ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
                ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
            ], after)

        if item == 'ClothesRed':
            return event_tools.createActionChain(flowchart, before, [
                ('EventFlags', 'SetFlag', {'symbol': RED_TUNIC_FOUND_FLAG, 'value': True}),
                ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Red_00', 'index': 0, 'restart': False, 'time': 3.58}),
                ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
                ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder_MaxUp', 'keepCarry': False, 'messageEntry': 'ClothesRed'})
            ], after)
        
        if item == 'ClothesBlue':
            return event_tools.createActionChain(flowchart, before, [
                ('EventFlags', 'SetFlag', {'symbol': BLUE_TUNIC_FOUND_FLAG, 'value': True}),
                ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Blue_00', 'index': 0, 'restart': False, 'time': 3.58}),
                ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
                ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder_MaxUp', 'keepCarry': False, 'messageEntry': 'ClothesBlue'})
            ], after)
        
        if item == 'ClothesGreen':
            return event_tools.createActionChain(flowchart, before, [
                # ('EventFlags', 'SetFlag', {'symbol': greenTunicFoundFlag, 'value': True}),
                ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Green_00', 'index': 0, 'restart': False, 'time': 3.58}),
                ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
                ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder_MaxUp', 'keepCarry': False, 'messageEntry': 'ClothesGreen'})
            ], after)
        
        if item == 'SecretMedicine':
            return event_tools.createActionChain(flowchart, before, [
                ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
                ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''}),
                ('Link', 'Heal', {'amount': 99})
        ], after)

        return event_tools.createActionChain(flowchart, before, [
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
            ], after)
        


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
        new_music = MUSIC_FILES[:]

        if not os.path.exists(dest):
            os.makedirs(dest)
        
        for file in files:
            if self.thread_active:
                track = file.removesuffix(MUSIC_SUFFIX)
                if track in MUSIC_FILES:
                    song = random.choice(new_music)
                    new_music.remove(song)
                    shutil.copy(f'{source}\\{file}', f'{dest}\\{song}{MUSIC_SUFFIX}')
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
        
        for room in INSTRUMENT_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', INSTRUMENT_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                
                with open(f'{self.rom_path}/region_common/level/{dirname}/{INSTRUMENT_ROOMS[room]}.leb', 'rb') as roomfile:
                    roomData = leb.Room(roomfile.read())
                                
                item = self.placements[room]
                itemIndex = self.placements['indexes'][room] if room in self.placements['indexes'] else -1
                
                level, location = Randomizers.instruments.write_room_data(roomData, room, self.item_defs[item]['model-path'],
                self.item_defs[item]['model-name'], INSTRUMENT_FLAGS[room])

                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{INSTRUMENT_ROOMS[room]}.leb', 'wb') as outFile:
                        outFile.write(roomData.repack())
                        self.progress_value += 1 # update progress bar
                        self.progress_update.emit(self.progress_value)
                
                itemGet = self.insertItemGetEvent(flow.flowchart, self.item_defs[item]['item-key'], itemIndex)
                Randomizers.instruments.write_instrument_event(flow, room, INSTRUMENT_FLAGS[room], itemGet, level, location)

        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/SinkingSword.bfevfl', flow)



    # heart piece rooms
    def makeHeartPieceChanges(self):
        # Open up ItemCommon to edit and save as HeartPiece
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/ItemCommon.bfevfl')
        self.addNeededActors(flow.flowchart)
        flow.flowchart.entry_points.pop(0) # get rid of the 'get' entry point
        
        for room in HEART_ROOMS:
            if self.thread_active:
                dirname = re.match('(.+)_\\d\\d[A-P]', HEART_ROOMS[room]).group(1)
                if not os.path.exists(f'{self.out_dir}/Romfs/region_common/level/{dirname}'):
                    os.makedirs(f'{self.out_dir}/Romfs/region_common/level/{dirname}')
                
                if HEART_ROOMS[room] in CHEST_ROOMS.values():
                    path = f'{self.out_dir}/Romfs'
                else:
                    path = self.rom_path
                
                with open(f'{path}/region_common/level/{dirname}/{HEART_ROOMS[room]}.leb', 'rb') as roomfile:
                    roomData = leb.Room(roomfile.read())
                
                item = self.placements[room]
                itemIndex = self.placements['indexes'][room] if room in self.placements['indexes'] else -1

                Randomizers.heart_pieces.write_room_data(roomData, room, HEART_FLAGS[room])
                                
                if self.thread_active:
                    with open(f'{self.out_dir}/Romfs/region_common/level/{dirname}/{HEART_ROOMS[room]}.leb', 'wb') as outFile:
                        outFile.write(roomData.repack())

                        if HEART_ROOMS[room] not in CHEST_ROOMS.values():
                            self.progress_value += 1 # update progress bar
                            self.progress_update.emit(self.progress_value)
                
                itemGet = self.insertItemGetEvent(flow.flowchart, self.item_defs[item]['item-key'], itemIndex, None, None)
                Randomizers.heart_pieces.write_heart_event(flow, room, HEART_FLAGS[room], itemGet)
        
        # we dont want to actually overwrite ItemCommon, so save it to a new file
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/HeartPiece.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)



    # make telephones switch tunics
    def makeTelephoneChanges(self):
        flow = event_tools.readFlow(f'{self.rom_path}/region_common/event/Telephone.bfevfl')
        self.addNeededActors(flow.flowchart)
        
        # telephone needs dialog query 'GetLastResult4' to get dialog result
        event_tools.addActorQuery(event_tools.findActor(flow.flowchart, 'Dialog'), 'GetLastResult4')

        greenGet = self.insertItemGetEvent(flow.flowchart, 'ClothesGreen', -1, None, None)

        redGet = self.insertItemGetEvent(flow.flowchart, 'ClothesRed', -1, None, None)
        checkRed = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': RED_TUNIC_FOUND_FLAG}, {0: None, 1: redGet})

        blueGet = self.insertItemGetEvent(flow.flowchart, 'ClothesBlue', -1, None, None)
        checkBlue = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': BLUE_TUNIC_FOUND_FLAG}, {0: None, 1: blueGet})

        Randomizers.tunic_switcher.write_swap_events(flow, greenGet, checkRed, checkBlue)
        
        if self.thread_active:
            event_tools.writeFlow(f'{self.out_dir}/Romfs/region_common/event/Telephone.bfevfl', flow)
            self.progress_value += 1 # update progress bar
            self.progress_update.emit(self.progress_value)
