import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers.data import MODEL_SIZES, MODEL_ROTATIONS

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

        for room in HEART_ROOMS:
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{HEART_ROOMS[room]}.leb')
            self.changeHeartPiece(flow.flowchart, room, room_data)
            self.parent.file_manager.writeFile(f'{HEART_ROOMS[room]}.leb', room_data)

        self.parent.file_manager.writeFile('SinkingSword.bfevfl', flow)


    def changeHeartPiece(self, flowchart, room, room_data):
        """Applies changes to both the Heart Piece actor and the event flowchart"""

        item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.trap_models)

        hp = [a for a in room_data.actors if a.type == 0xB0]
        act = hp[0]

        get_anim = self.parent.item_get_manager.get(flowchart, room)

        event_tools.addEntryPoint(flowchart, room)
        event_tools.createActionChain(flowchart, room, [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': HEART_FLAGS[room], 'value': True})
        ], get_anim)

        if room in sunken:
            if model_name not in ("HeartPiece", "HeartContainer"):
                act.posY += 0.25 # raise them up 1/6 of a tile
                act.scaleX = 0.75
                act.scaleY = 0.75
                act.scaleZ = 0.75
        else:
            # for freestanding heart pieces, shrink the actor if the model will be big
            # we might want a separate model size list, for now this should be fine
            if model_name not in ("HeartPiece", "HeartContainer"):
                act.scaleX = 0.55
                act.scaleY = 0.55
                act.scaleZ = 0.55

        # parameter[0] is index, which doesnt matter because we make ItemHeartPiece ignore inventory for spawning
        act.parameters[1] = bytes(model_path, 'utf-8')
        act.parameters[2] = bytes(model_name, 'utf-8')
        act.parameters[3] = bytes(room, 'utf-8') # entry point
        act.parameters[4] = bytes(HEART_FLAGS[room], 'utf-8') # flag which controls if the heart piece appears or not

        if item_key == 'Seashell':
            act.parameters[5] = bytes('true', 'utf-8')
        else:
            act.parameters[5] = bytes('false', 'utf-8')

        if model_name in MODEL_SIZES:
            size = MODEL_SIZES[model_name]
            act.scaleX *= size
            act.scaleY *= size
            act.scaleZ *= size
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

HEART_FLAGS = {
    'animal-village-northwest': 'AnimalVillageHeartGet',
    'animal-village-cave': 'AnimalVillageCaveHeartGet',
    'taltal-entrance-blocks': 'TaltalEntranceBlocksHeartGet',
    'north-wasteland': 'NorthWastelandHeartGet',
    'desert-cave': 'DesertCaveHeartGet',
    'graveyard-cave': 'GraveyardCaveHeartGet',
    'mabe-well': 'MabeWellHeartGet',
    'ukuku-cave-west-loose': 'UkukuCaveWestHeartGet',
    'ukuku-cave-east-loose': 'UkukuCaveEastHeartGet',
    'bay-passage-sunken': 'BayPassageHeartGet',
    'river-crossing-cave': 'RiverCrossingHeartGet',
    'rapids-west-island': 'RapidsWestHeartGet',
    'rapids-ascent-cave': 'RapidsAscentHeartGet',
    'kanalet-moat-south': 'KanaletMoatHeartGet',
    'south-bay-sunken': 'SouthBayHeartGet',
    'taltal-crossing-cave': 'TaltalCrossingHeartGet',
    'taltal-east-drop': 'TaltalEastHeartGet',
    'taltal-west-escape': 'TaltalWestHeartGet',
    'above-turtle-rock': 'TurtleRockHeartGet',
    'pothole-north': 'PotholeHeartGet',
    'woods-crossing-cave-loose': 'WoodsCrossingHeartGet',
    'woods-north-cave-loose': 'WoodsNorthCaveHeartGet',
    'diamond-island': 'DiamondIslandHeartGet'
}
