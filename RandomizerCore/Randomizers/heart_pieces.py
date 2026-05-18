import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import item_get
from RandomizerCore.Randomizers.data import HEART_FLAGS, MODEL_SIZES, MODEL_ROTATIONS

sunken = [
    'taltal-east-drop',
    'south-bay-sunken',
    'bay-passage-sunken',
    'river-crossing-cave',
    'kanalet-moat-south'
]


class HeartPieceRandomizer:
    def __init__(self, mod_generator):
        self.parent = mod_generator
        self.makeHeartPieceChanges()


    def makeHeartPieceChanges(self):
        """Iterates through the nonsunken Heart Piece rooms and edits the Heart Piece actor data"""

        flow = self.parent.file_manager.readFile('SinkingSword.bfevfl')

        sunken = [
            'taltal-east-drop',
            'south-bay-sunken',
            'bay-passage-sunken',
            'river-crossing-cave',
            'kanalet-moat-south'
        ]
        non_sunken = (x for x in HEART_ROOMS if x not in sunken)

        for room in non_sunken:
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{HEART_ROOMS[room]}.leb')
            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.trap_models)
            self.changeHeartPiece(flow.flowchart, item_key, item_index, model_path, model_name, room, room_data)
            self.parent.file_manager.writeFile(f'{HEART_ROOMS[room]}.leb', room_data)

        self.parent.file_manager.writeFile('SinkingSword.bfevfl', flow)


    def changeHeartPiece(self, flowchart, item_key, item_index, model_path, model_name, room, room_data):
        """Applies changes to both the Heart Piece actor and the event flowchart"""

        hp = [a for a in room_data.actors if a.type == 0xB0]
        act = hp[0]

        if item_key[:3] == 'Rup': # no need for a fancy animation for rupees, just give them to the player
            get_anim = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
        else:
            get_anim = item_get.insertItemGetAnimation(flowchart, item_key, item_index)

        event_tools.addEntryPoint(flowchart, room)
        event_tools.createActionChain(flowchart, room, [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': HEART_FLAGS[room], 'value': True})
        ], get_anim)

        act.type = 0x194 # sinking sword

        if room in sunken:
            if room == 'taltal-east-drop':
                act.posY += 2 # cannot see the item in the water, so let's just have it float on the water lol
            # else:
            #     act.posY += 0.5 # raise others up by 1/3 tile
        else:
            if room == 'mabe-well':
                act.posY += 0.5 # this one always ends up clipped into the ground more, so raise by 1/3 tile
            else:
                act.posY += 0.375 # raise all others by 1/4 tile

        act.parameters[0] = bytes(model_path, 'utf-8')
        act.parameters[1] = bytes(model_name, 'utf-8')
        act.parameters[2] = bytes(room, 'utf-8') # entry point
        act.parameters[3] = bytes(HEART_FLAGS[room], 'utf-8') # flag which controls if the heart piece appears or not

        if item_key == 'Seashell':
            act.parameters[4] = bytes('true', 'utf-8')
        else:
            act.parameters[4] = bytes('false', 'utf-8')

        if model_name in MODEL_SIZES:
            size = MODEL_SIZES[model_name]
            act.scaleX = size
            act.scaleY = size
            act.scaleZ = size
        if model_name in MODEL_ROTATIONS:
            act.rotY = MODEL_ROTATIONS[model_name]


HEART_ROOMS = {
    'animal-village-northwest': 'Field_13L',
    'animal-village-cave': 'AnimalVillageCave_01A',
    'taltal-entrance-blocks': 'Tamaranch04_03B',
    'north-wasteland': 'Field_05H',
    'desert-cave': 'LanmolaCave_01A',
    'graveyard-cave': 'UnderGrave_01B',
    'mabe-well': 'TownWell_01A',
    'ukuku-cave-west-loose': 'UkukuCave01_01A',
    'ukuku-cave-east-loose': 'UkukuCave02_01B',
    'bay-passage-sunken': 'MadBattersWellEnter_01B',
    'river-crossing-cave': 'AnimalVillageEnter_01B',
    'rapids-west-island': 'Field_06M',
    'rapids-ascent-cave': 'RapidsRideExit_01A',
    'kanalet-moat-south': 'Field_08J',
    'south-bay-sunken': 'Field_15J',
    'taltal-crossing-cave': 'Tamaranch04_02C',
    'taltal-east-drop': 'EagleTowerExit_01A',
    'taltal-west-escape': 'Field_03B',
    'above-turtle-rock': 'Field_01A',
    'pothole-north': 'Field_12H',
    'woods-crossing-cave-loose': 'MysteriousWoodsCave01_01A',
    'woods-north-cave-loose': 'MysteriousWoodsCave02_01A',
    'diamond-island': 'Field_05E'
}
