import Tools.event_tools as event_tools
from Randomizers import item_get
from Randomizers import data



# sunken = [
#     'taltal-east-drop',
#     'south-bay-sunken',
#     'bay-passage-sunken',
#     'river-crossing-cave',
#     'kanalet-moat-south'
# ]



def changeHeartPiece(flowchart, item_key, item_index, model_path, model_name, room, room_data):
    """Applies changes to both the Heart Piece actor and the event flowchart"""

    if item_key[:3] == 'Rup': # no need for a fancy animation for rupees, just give them to the player
        itemGet = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
        {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
    else:
        itemGet = item_get.insertItemGetAnimation(flowchart, item_key, item_index)
    
    event_tools.addEntryPoint(flowchart, room)
    event_tools.createActionChain(flowchart, room, [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.HEART_FLAGS[room], 'value': True})
    ], itemGet)

    for act in room_data.actors:
        if act.type == 0xB0:

            act.type = 0x194 # sinking sword

            # if room in sunken:
            #     if room not in ['taltal-east-drop', 'river-crossing-cave']:
            #         act.Z += int(393216 * 4) # move them up a lot
            # else:
            act.Z += int(393216 / 2) # standing heart pieces go half a tile upwards
            
            act.parameters[0] = bytes('ObjSinkingSword.bfres' if item_key == 'SwordLv1' else model_path, 'utf-8')
            act.parameters[1] = bytes('SinkingSword' if item_key == 'SwordLv1' else model_name, 'utf-8')
            act.parameters[2] = bytes(room, 'utf-8') # entry point
            act.parameters[3] = bytes(data.HEART_FLAGS[room], 'utf-8') # flag which controls if the heart piece appears or not
