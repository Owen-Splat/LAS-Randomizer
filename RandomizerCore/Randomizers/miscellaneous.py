import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import item_get
from RandomizerCore.Randomizers.data import (BEACH_LOOSE_FLAG, WOODS_LOOSE_FLAG, DREAM_SHRINE_FLAG,
ROOSTER_CAVE_FLAG, MERMAID_CAVE_FLAG, MODEL_SIZES, MODEL_ROTATIONS)


def changeSunkenSword(flowchart, item_key, item_index, model_path, model_name, room, music_shuffled):
    if music_shuffled:
        end_ev = None
        del event_tools.findEvent(flowchart, 'Event0').data.forks[0]
    else:
        end_ev = 'Event8'
    
    if item_key[:3] == 'Rup': # no need for a fancy animation for rupees, just give them to the player
        rup_collect = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False}, end_ev)
        event_tools.insertEventAfter(flowchart, 'Event5', rup_collect)
    else:
        item_get.insertItemGetAnimation(flowchart, item_key, item_index, 'Event5', end_ev)

    fork = event_tools.findEvent(flowchart, 'Event0')
    fork.data.forks.pop(0) # remove the itemget animation event
    event_tools.removeEventAfter(flowchart, 'Event10')
    # event_tools.findEvent(flowchart, 'Event1').data.params.data['itemType'] = -1

    fork = event_tools.findEvent(flowchart, 'Event8')
    fork.data.forks.pop(1) # remove the sword spin attack animation event

    # update the flag set when getting this item
    flag_set = event_tools.findEvent(flowchart, 'Event2')
    flag_set.data.params.data['symbol'] = BEACH_LOOSE_FLAG

    # set y-rotation to be 0, if it's something that needs flipped, it will be handled later
    act = room.actors[4]
    act.rotY = 0.0

    # Keep the normal model if it's a sword
    act.parameters[0] = bytes(model_path, 'utf-8')
    act.parameters[1] = bytes(model_name, 'utf-8')
    act.parameters[2] = bytes('examine', 'utf-8')
    act.parameters[3] = bytes(BEACH_LOOSE_FLAG, 'utf-8')

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


def _change_loose_pickup(flowchart, item_key, item_index, model_path,
                         model_name, room, actor_index, actor_type,
                         entry_point, collection_flag, reset_rotation):
    """Share the reward flow while retaining each location's actor setup."""
    if item_key[:3] == 'Rup':
        reward_event = event_tools.createActionEvent(
            flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
    else:
        reward_event = item_get.insertItemGetAnimation(flowchart, item_key, item_index)

    event_tools.addEntryPoint(flowchart, entry_point)
    event_tools.createActionChain(flowchart, entry_point, [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': collection_flag, 'value': True}),
    ], reward_event)

    actor = room.actors[actor_index]
    actor.type = actor_type
    if reset_rotation:
        actor.rotY = 0
    actor.parameters[0] = model_path.encode('utf-8')
    actor.parameters[1] = model_name.encode('utf-8')
    actor.parameters[2] = entry_point.encode('utf-8')
    actor.parameters[3] = collection_flag.encode('utf-8')
    actor.parameters[4] = b'true' if item_key == 'Seashell' else b'false'
    if model_name in MODEL_SIZES:
        actor.scaleX = actor.scaleY = actor.scaleZ = MODEL_SIZES[model_name]
    if model_name in MODEL_ROTATIONS:
        actor.rotY = MODEL_ROTATIONS[model_name]



def changeMushroom(flowchart, item_key, item_index, model_path, model_name, room):
    _change_loose_pickup(flowchart, item_key, item_index, model_path, model_name,
                         room, 3, 0x194, 'Woods', WOODS_LOOSE_FLAG, False)



def changeOcarina(flowchart, item_key, item_index, model_path, model_name, room):
    _change_loose_pickup(flowchart, item_key, item_index, model_path, model_name,
                         room, 5, 0x8E, 'DreamShrine', DREAM_SHRINE_FLAG, False)



def changeBirdKey(flowchart, item_key, item_index, model_path, model_name, room):
    _change_loose_pickup(flowchart, item_key, item_index, model_path, model_name,
                         room, 0, 0x194, 'TalTal', ROOSTER_CAVE_FLAG, False)



def changeLens(flowchart, item_key, item_index, model_path, model_name, room):
    _change_loose_pickup(flowchart, item_key, item_index, model_path, model_name,
                         room, 7, 0x194, 'MermaidCave', MERMAID_CAVE_FLAG, True)
