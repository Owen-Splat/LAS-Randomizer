import Tools.event_tools as event_tools
import Randomizers.item_get as item_get
from Randomizers.data import HEART_FLAGS



def changeHeartPiece(flowchart, itemKey, itemIndex, modelPath, modelName, room, roomData):
    if itemKey[:3] == 'Rup': # no need for a fancy animation for rupees, just give them to the player
        itemGet = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
        {'itemKey': itemKey, 'count': 1, 'index': itemIndex, 'autoEquip': False})
    else:
        itemGet = item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex)
    
    event_tools.addEntryPoint(flowchart, room)
    event_tools.createActionChain(flowchart, room, [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': HEART_FLAGS[room], 'value': True})
    ], itemGet)

    for act in roomData.actors:
        if act.type == 0xB0:

            act.type = 0x194 # sinking sword

            act.Z = int(act.Z + (393216 / 2)) # move item half a tile upwards
            
            # # # change the index of the heart piece which controls whether it shows up or not
            # # # setting the byte as anything besides a number means they go away once you collect a single heart piece
            # # # setting the index higher than the amount of heart pieces seems to make it look for something else, not quite sure what
            # act.parameters[0] = int(42069) # meme number because why not, lets see what happens
            
            act.parameters[0] = bytes(modelPath, 'utf-8')
            act.parameters[1] = bytes(modelName, 'utf-8')
            act.parameters[2] = bytes(room, 'utf-8') # entry point
            act.parameters[3] = bytes(HEART_FLAGS[room], 'utf-8') # flag which controls if the heart piece appears or not
