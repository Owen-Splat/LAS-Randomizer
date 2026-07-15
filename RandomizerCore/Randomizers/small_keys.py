import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers.golden_leaves import createRoomKey

class KeyRandomizer:
    def __init__(self, mod_generator):
        self.parent = mod_generator
        self.makeSmallKeyChanges()


    def makeSmallKeyChanges(self):
        """Patch SmallKey event and LEB files for rooms with small key drops to change them into other items"""

        # Open up the SmallKey event to be ready to edit
        flow = self.parent.file_manager.readFile('SmallKey.bfevfl')

        if self.parent.settings["Key Animations"]:
            self.makeKeysFaster(flow.flowchart)

        for room in SMALL_KEY_ROOMS:
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{SMALL_KEY_ROOMS[room]}.leb')
            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.dungeon_trap_models)
            self.writeKeyEvent(flow.flowchart, room)
            room_data.setSmallKeyParams(model_path, model_name, room, item_key)
            self.parent.file_manager.writeFile(f'{SMALL_KEY_ROOMS[room]}.leb', room_data)

            if room == 'D4-sunken-item': # special case. need to write the same data in 06A
                room_data = self.parent.file_manager.readFile('Lv04AnglersTunnel_06A.leb')
                room_data.setSmallKeyParams(model_path, model_name, room, item_key)
                self.parent.file_manager.writeFile('Lv04AnglersTunnel_06A.leb', room_data)

        if self.parent.thread_active:
            self.makeGoldenLeafChanges(flow)


    def makeGoldenLeafChanges(self, flow):
        '''Make small key actors spawn for the golden leaf checks'''

        for room in GOLDEN_LEAF_ROOMS:
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{GOLDEN_LEAF_ROOMS[room]}.leb')
            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.trap_models)
            createRoomKey(room_data, room, self.parent.flag_manager.flags)
            self.writeKeyEvent(flow.flowchart, room)
            room_data.setSmallKeyParams(model_path, model_name, room, item_key)
            self.parent.file_manager.writeFile(f'{GOLDEN_LEAF_ROOMS[room]}.leb', room_data)

        self.parent.file_manager.writeFile('SmallKey.bfevfl', flow)


    def writeKeyEvent(self, flowchart, room):
        """Adds a new entry point to the SmallKey event flow for each key room, and inserts an ItemGetAnimation to it"""
        
        item_event = self.parent.item_get_manager.get(flowchart, room)

        event_tools.addEntryPoint(flowchart, room)

        event_tools.createActionChain(flowchart, room, [
            ('SmallKey', 'Deactivate', {}),
            ('SmallKey', 'SetActorSwitch', {'value': True, 'switchIndex': 1}),
            ('SmallKey', 'Destroy', {})
        ], item_event)


    def makeKeysFaster(self, flowchart):
        '''Gives control back to the player soon after triggering the key to fall'''
        
        event_tools.insertEventAfter(flowchart, 'pop', 'Event5')
        event_tools.insertEventAfter(flowchart, 'Event3', None)
        event_tools.findEvent(flowchart, 'Event3').data.params.data['time'] = 2.0

        event_tools.insertEventAfter(flowchart, 'Lv4_04E_pop', 'Event7')
        event_tools.insertEventAfter(flowchart, 'Event10', None)


SMALL_KEY_ROOMS = {
 'D1-beetles': 'Lv01TailCave_08C',
 'D2-double-stalfos': 'Lv02BottleGrotto_07D',
 'D2-double-shy-guys': 'Lv02BottleGrotto_07F',
 'D3-pre-boss': 'Lv03KeyCavern_08G',
 'D3-triple-bombites': 'Lv03KeyCavern_01B',
 'D3-pairodds': 'Lv03KeyCavern_03A',
 'D3-five-zols': 'Lv03KeyCavern_04C',
 'D3-basement-north': 'Lv03KeyCavern_03G',
 'D3-basement-west': 'Lv03KeyCavern_04F',
 'D3-basement-south': 'Lv03KeyCavern_05G',
 'D4-sunken-item': 'Lv04AnglersTunnel_04E', # Also Lv04AnglersTunnel_06A, but leave vanilla for now.
 'D5-crystal-blocks': 'Lv05CatfishsMaw_01C',
 'D6-wizzrobe-pegs': 'Lv06FaceShrine_03D',
 'D6-tile-room': 'Lv06FaceShrine_05D',
 'D7-like-likes': 'Lv07EagleTower_08D',
 'D7-hinox': 'Lv07EagleTower_04A',
 'D8-gibdos': 'Lv08TurtleRock_03G',
 'D8-statue': 'Lv08TurtleRock_04C',
 'D8-west-vire': 'Lv08TurtleRock_06A',
 'D8-east-roomba': 'Lv08TurtleRock_07G',
 'D0-north-orbs': 'Lv10ClothesDungeon_05E',
 'D0-east-color-puzzle': 'Lv10ClothesDungeon_05F',
 'pothole-final': 'Field_13G'
}

GOLDEN_LEAF_ROOMS = {
    'kanalet-crow': 'Field_06I',
    'kanalet-mad-bomber': 'Field_06K',
    'kanalet-kill-room': 'KanaletCastle_02A',
    'kanalet-bombed-guard': 'KanaletCastle_01C',
    'kanalet-final-guard': 'KanaletCastle_01D'
}
