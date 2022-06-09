import Tools.event_tools as event_tools



def write_key_event(flow, room, itemGetEvent):
    event_tools.addEntryPoint(flow.flowchart, room)

    event_tools.createActionChain(flow.flowchart, room, [
        ('SmallKey', 'Deactivate', {}),
        ('SmallKey', 'SetActorSwitch', {'value': True, 'switchIndex': 1}),
        ('SmallKey', 'Destroy', {})
    ], itemGetEvent)

    return flow
