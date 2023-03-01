import Tools.event_tools as event_tools
from Randomizers import item_get, data



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

    # just like the lens, this actor is rotated 180 degrees on the Y axis
    # this makes it hard to differenciate between heart pieces and containers as both are grey from the back
    room.actors[4].rotY = 180.0 if item_key == 'SwordLv1' else 0

    # Keep the normal model if it's a sword
    room.actors[4].parameters[0] = bytes('ObjSinkingSword.bfres' if item_key == 'SwordLv1' else model_path, 'utf-8')
    room.actors[4].parameters[1] = bytes('SinkingSword' if item_key == 'SwordLv1' else model_name, 'utf-8')
    room.actors[4].parameters[2] = bytes('examine', 'utf-8')
    room.actors[4].parameters[3] = bytes('SwordGet', 'utf-8')

    if item_key == 'Seashell':
        room.actors[4].parameters[4] = bytes('true', 'utf-8')
    else:
        room.actors[4].parameters[4] = bytes('false', 'utf-8')



def changeBirdKey(flowchart, item_key, item_index, model_path, model_name, room):
    if item_key[:3] == 'Rup': # no need for a fancy animation for rupees, just give them to the player
        get_anim = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
    else:
        get_anim = item_get.insertItemGetAnimation(flowchart, item_key, item_index)

    event_tools.addEntryPoint(flowchart, 'TalTal')
    event_tools.createActionChain(flowchart, 'TalTal', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.ROOSTER_CAVE_FLAG, 'value': True})
    ], get_anim)

    room.actors[0].type = 0x194 # sinking sword
    room.actors[0].parameters[0] = bytes('ObjSinkingSword.bfres' if item_key == 'SwordLv1' else model_path, 'utf-8')
    room.actors[0].parameters[1] = bytes('SinkingSword' if item_key == 'SwordLv1' else model_name, 'utf-8')
    room.actors[0].parameters[2] = bytes('TalTal', 'utf-8')
    room.actors[0].parameters[3] = bytes(data.ROOSTER_CAVE_FLAG, 'utf-8')

    if item_key == 'Seashell':
        room.actors[0].parameters[4] = bytes('true', 'utf-8')
    else:
        room.actors[0].parameters[4] = bytes('false', 'utf-8')



def changeOcarina(flowchart, item_key, item_index, model_path, model_name, room):
    if item_key[:3] == 'Rup': # no need for a fancy animation for rupees, just give them to the player
        get_anim = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
    else:
        get_anim = item_get.insertItemGetAnimation(flowchart, item_key, item_index)

    event_tools.addEntryPoint(flowchart, 'DreamShrine')
    event_tools.createActionChain(flowchart, 'DreamShrine', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.DREAM_SHRINE_FLAG, 'value': True})
    ], get_anim)

    room.actors[5].type = 0x8E # yoshi doll, will disappear once you have yoshi, but the player never actually obtains it :)
    room.actors[5].parameters[0] = bytes('ObjSinkingSword.bfres' if item_key == 'SwordLv1' else model_path, 'utf-8')
    room.actors[5].parameters[1] = bytes('SinkingSword' if item_key == 'SwordLv1' else model_name, 'utf-8')
    room.actors[5].parameters[2] = bytes('DreamShrine', 'utf-8')
    room.actors[5].parameters[3] = bytes(data.DREAM_SHRINE_FLAG, 'utf-8') # category 1

    if item_key == 'Seashell':
        room.actors[5].parameters[4] = bytes('true', 'utf-8')
    else:
        room.actors[5].parameters[4] = bytes('false', 'utf-8')



def changeMushroom(flowchart, item_key, item_index, model_path, model_name, room):
    if item_key[:3] == 'Rup': # no need for a fancy animation for rupees, just give them to the player
        get_anim = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
    else:
        get_anim = item_get.insertItemGetAnimation(flowchart, item_key, item_index)

    event_tools.addEntryPoint(flowchart, 'Woods')
    event_tools.createActionChain(flowchart, 'Woods', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.WOODS_LOOSE_FLAG, 'value': True})
    ], get_anim)

    room.actors[3].type = 0x194 # sinking sword
    room.actors[3].parameters[0] = bytes('ObjSinkingSword.bfres' if item_key == 'SwordLv1' else model_path, 'utf-8')
    room.actors[3].parameters[1] = bytes('SinkingSword' if item_key == 'SwordLv1' else model_name, 'utf-8')
    room.actors[3].parameters[2] = bytes('Woods', 'utf-8')
    room.actors[3].parameters[3] = bytes(data.WOODS_LOOSE_FLAG, 'utf-8')

    if item_key == 'Seashell':
        room.actors[3].parameters[4] = bytes('true', 'utf-8')
    else:
        room.actors[3].parameters[4] = bytes('false', 'utf-8')



def changeLens(flowchart, item_key, item_index, model_path, model_name, room):
    if item_key[:3] == 'Rup': # no need for a fancy animation for rupees, just give them to the player
        get_anim = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
            {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
    else:
        get_anim = item_get.insertItemGetAnimation(flowchart, item_key, item_index)

    event_tools.addEntryPoint(flowchart, 'MermaidCave')
    event_tools.createActionChain(flowchart, 'MermaidCave', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.MERMAID_CAVE_FLAG, 'value': True})
    ], get_anim)

    room.actors[7].type = 0x194 # sinking sword
    room.actors[7].rotY = 0 # rotate to be facing the screen
    room.actors[7].parameters[0] = bytes('ObjSinkingSword.bfres' if item_key == 'SwordLv1' else model_path, 'utf-8')
    room.actors[7].parameters[1] = bytes('SinkingSword' if item_key == 'SwordLv1' else model_name, 'utf-8')
    room.actors[7].parameters[2] = bytes('MermaidCave', 'utf-8')
    room.actors[7].parameters[3] = bytes(data.MERMAID_CAVE_FLAG, 'utf-8')

    if item_key == 'Seashell':
        room.actors[7].parameters[4] = bytes('true', 'utf-8')
    else:
        room.actors[7].parameters[4] = bytes('false', 'utf-8')
