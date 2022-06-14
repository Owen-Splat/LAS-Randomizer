import Tools.event_tools as event_tools



def writeHeartEvent(flow, room, flag, itemGetEvent):
    event_tools.addEntryPoint(flow.flowchart, room)

    event_tools.createActionChain(flow.flowchart, room, [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': flag, 'value': True})
    ], itemGetEvent)



def writeRoomData(roomData, modelPath, modelName, room, flag):
    for act in roomData.actors:
        if act.type == 0xB0:
            act.type = 0x8D # turn actor into bird key
            # act.Z = int(act.Z + (393216 / 2)) # move item half a tile upwards
            act.parameters[0] = bytes(modelPath, 'utf-8')
            act.parameters[1] = bytes(modelName, 'utf-8')
            act.parameters[2] = bytes(room, 'utf-8') # entry point
            act.parameters[3] = bytes(flag, 'utf-8') # flag which controls if the heart piece appears or not
