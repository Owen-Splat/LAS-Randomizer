import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers.data import MODEL_SIZES, MODEL_ROTATIONS, DUNGEON_ENTRANCES
import re


class InstrumentRandomizer:
    def __init__(self, mod_generator):
        self.parent = mod_generator
        self.makeInstrumentChanges()


    def makeInstrumentChanges(self):
        """Iterates through the Instrument rooms and edits the Instrument actor data"""

        # Open up the already modded SinkingSword eventflow to make new events
        flow = self.parent.file_manager.readFile('SinkingSword.bfevfl')

        for room in INSTRUMENT_ROOMS:
            if not self.parent.thread_active:
                break

            room_data = self.parent.file_manager.readFile(f'{INSTRUMENT_ROOMS[room]}.leb')

            if self.parent.settings["Shuffled Dungeons"]:
                cur_dun = re.match('(.+)_\\d\\d[A-Z]', INSTRUMENT_ROOMS[room]).group(1)
                for k,v in DUNGEON_ENTRANCES.items():
                    dun = re.match('(.+)_\\d\\d[A-Z]', v[0]).group(1)
                    if dun == cur_dun:
                        ent_keys = list(self.parent.placements['dungeon-entrances'].keys())
                        ent_values = list(self.parent.placements['dungeon-entrances'].values())
                        d = DUNGEON_ENTRANCES[ent_keys[ent_values.index(k)]]
                        destination = d[2] + d[3]
            else:
                destination = None

            self.changeInstrument(flow.flowchart, room, room_data, destination)

            self.parent.file_manager.writeFile(f'{INSTRUMENT_ROOMS[room]}.leb', room_data)

        self.parent.file_manager.writeFile('SinkingSword.bfevfl', flow)


    def changeInstrument(self, flowchart, room, room_data, destination=None):
        """Applies changes to both the Instrument actor and the event flowchart"""

        item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.dungeon_trap_models)

        if room == 'D6-instrument':
            act = room_data.actors[1]
        else:
            act = room_data.actors[0]

        if destination is None:
            # store the level and location for the leveljump event since we will overwrite these parameters
            level = str(act.parameters[0], 'utf-8')
            location = str(act.parameters[1], 'utf-8')
        else:
            level = re.match('(.+)_\\d\\d[A-Z]', destination).group(1)
            location = destination

        act.type = 0x194 # ObjSinkingSword so that the player needs to press A to grab
        act.posY += 0.5 # they are halfway into the ground, so raise them up by 1/3 of a tile
        act.parameters[0] = bytes(model_path, 'utf-8')
        act.parameters[1] = bytes(model_name, 'utf-8')
        act.parameters[2] = bytes(room, 'utf-8') # entry point that we write to flow
        act.parameters[3] = bytes(INSTRUMENT_FLAGS[room], 'utf-8') # flag for if item appears

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

        fade_event = self.insertInstrumentFadeEvent(flowchart, level, location)
        instrument_get = self.parent.item_get_manager.get(flowchart, room, None, fade_event)

        event_tools.addEntryPoint(flowchart, room)
        event_tools.createActionChain(flowchart, room, [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': INSTRUMENT_FLAGS[room], 'value': True})
        ], instrument_get)


    def insertInstrumentFadeEvent(self, flowchart, level, location):
        shine_effect = event_tools.createActionChain(flowchart, None, [
            ('Audio', 'StopAllBGM', {'duration': 1.0}),
            ('Link', 'PlayInstrumentShineEffect', {}),
            ('Timer', 'Wait', {'time': 2})
        ], None)

        level_jump = event_tools.createActionChain(flowchart, None, [
            ('Timer', 'Wait', {'time': 2}),
            ('GameControl', 'RequestLevelJump', {'level': level, 'locator': location, 'offsetX': 0.0, 'offsetZ': 0.0}),
            ('GameControl', 'RequestAutoSave', {})
        ], None)

        return event_tools.createForkEvent(flowchart, shine_effect, [
            event_tools.createActionEvent(flowchart, 'Audio', 'StopOtherThanSystemSE', {'duration': 3.0}),
            event_tools.createActionEvent(flowchart, 'Audio', 'PlayOneshotSystemSE', {'label': 'SE_ENV_GET_INST_WHITEOUT2', 'pitch': 1.0, 'volume': 1.0}),
            event_tools.createActionChain(flowchart, None, [
                ('Fade', 'StartPreset', {'preset': 3}),
                ('Fade', 'StartParam', {'colorB': 0.9, 'colorG': 0.9, 'colorR': 0.9, 'mode': 2, 'time': 0.75})
            ])
        ], level_jump)[0]


INSTRUMENT_FLAGS = {
    'D1-instrument': 'TailCaveInstrumentGet',
    'D2-instrument': 'BottleGrottoInstrumentGet',
    'D3-instrument': 'KeyCavernInstrumentGet',
    'D4-instrument': 'AnglersTunnelInstrumentGet',
    'D5-instrument': 'CatfishsMawInstrumentGet',
    'D6-instrument': 'FaceShrineInstrumentGet',
    'D7-instrument': 'EaglesTowerInstrumentGet',
    'D8-instrument': 'TurtleRockInstrumentGet'
}

INSTRUMENT_ROOMS = {
    'D1-instrument': 'Lv01TailCave_03G',
    'D2-instrument': 'Lv02BottleGrotto_04F',
    'D3-instrument': 'Lv03KeyCavern_06G',
    'D4-instrument': 'Lv04AnglersTunnel_03B',
    'D5-instrument': 'Lv05CatfishsMaw_01D',
    'D6-instrument': 'Lv06FaceShrine_03E',
    'D7-instrument': 'Lv07EagleTower_02G',
    'D8-instrument': 'Lv08TurtleRock_01D'
}
