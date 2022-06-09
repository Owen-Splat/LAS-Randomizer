import Tools.event_tools as event_tools



def write_heart_event(flow, room, flag, itemGetEvent):
    event_tools.addEntryPoint(flow.flowchart, room)

    event_tools.createActionChain(flow.flowchart, room, [
        ('Item', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': flag, 'value': True})
    ], itemGetEvent)



def write_room_data(roomData, room, flag):
    for act in roomData.actors:
        if act.type == 0xB0:
            act.parameters[0] = False # checks to see if you own the index for if it appears or not
            # act.parameters[1] = bytes(self.item_defs[item]['model-path'], 'utf-8')
            # act.parameters[2] = bytes(self.item_defs[item]['model-name'], 'utf-8')
            act.parameters[1] = bytes(room, 'utf-8') # entry point that we write to flow
            act.parameters[2] = bytes(flag, 'utf-8') # flag for if item appears
