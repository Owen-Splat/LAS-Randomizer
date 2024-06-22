import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import item_get
from RandomizerCore.Randomizers.data import INSTRUMENT_FLAGS, MODEL_SIZES, MODEL_ROTATIONS
import re



def changeInstrument(flowchart, item_key, item_index, model_path, model_name, room, room_data, destination=None):
    """Applies changes to both the Instrument actor and the event flowchart"""
    
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

    act.type = 0x8E # yoshi doll, will disappear once you have yoshi, but the player never actually obtains it :)
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

    fade_event = insertInstrumentFadeEvent(flowchart, level, location)
    instrument_get = item_get.insertItemGetAnimation(flowchart, item_key, item_index, None, fade_event)

    event_tools.addEntryPoint(flowchart, room)
    event_tools.createActionChain(flowchart, room, [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': INSTRUMENT_FLAGS[room], 'value': True})
    ], instrument_get)



def insertInstrumentFadeEvent(flowchart, level, location):
    shine_effect = event_tools.createActionChain(flowchart, None, [
        ('Audio', 'StopAllBGM', {'duration': 1.0}),
        ('Link', 'PlayInstrumentShineEffect', {}),
        ('Timer', 'Wait', {'time': 2})
        # ('Audio', 'StopOtherThanSystemSE', {'duration': 3.0}),
        # ('Audio', 'PlayOneshotSystemSE', {'label': 'SE_ENV_GET_INST_WHITEOUT2', 'pitch': 1.0, 'volume': 1.0}),
        # ('Fade', 'StartPreset', {'preset': 3}),
        # ('Fade', 'StartParam', {'colorB': 0.9, 'colorG': 0.9, 'colorR': 0.9, 'mode': 2, 'time': 0.75}),
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