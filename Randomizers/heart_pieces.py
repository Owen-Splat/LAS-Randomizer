import Tools.event_tools as event_tools
from Randomizers import item_get
from Randomizers import data



sunken = [
    'taltal-east-drop',
    'south-bay-sunken',
    'bay-passage-sunken',
    'river-crossing-cave',
    'kanalet-moat-south'
]



def changeHeartPiece(flowchart, itemKey, itemIndex, modelPath, modelName, room, roomData):
    if itemKey[:3] == 'Rup': # no need for a fancy animation for rupees, just give them to the player
        itemGet = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
        {'itemKey': itemKey, 'count': 1, 'index': itemIndex, 'autoEquip': False})
    else:
        itemGet = item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex)
    
    event_tools.addEntryPoint(flowchart, room)
    event_tools.createActionChain(flowchart, room, [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': data.HEART_FLAGS[room], 'value': True})
    ], itemGet)

    for act in roomData.actors:
        if act.type == 0xB0:

            act.type = 0x194 # sinking sword

            if room in sunken:
                if room not in ['taltal-east-drop', 'river-crossing-cave']:
                    act.Z += int(393216 * 4) # move them up a bit
                
                act.parameters[3] = bytes('Flippers', 'utf-8')
                act.parameters[4] = bytes('false', 'utf-8') # do not let you grab sunken heart pieces by pressing A
            
            else:
                act.Z += int(393216 / 2) # standing heart pieces go half a tile upwards
                act.parameters[3] = b''
                act.parameters[4] = bytes('true', 'utf-8') # let the player grab standing ones
            
            act.parameters[0] = bytes(modelPath, 'utf-8')
            act.parameters[1] = bytes(modelName, 'utf-8')
            act.parameters[2] = bytes(room, 'utf-8') # entry point
            act.parameters[5] = bytes(data.HEART_FLAGS[room], 'utf-8') # flag which controls if the heart piece appears or not
