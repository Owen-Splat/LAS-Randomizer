import Tools.event_tools as event_tools



def write_swap_events(flow, greenGetEvent, checkRedEvent, checkBlueEvent):
    
    getRedBlue = has_green_event(flow.flowchart, checkRedEvent, checkBlueEvent)
    getBlueGreen = has_red_event(flow.flowchart, checkBlueEvent, greenGetEvent)
    getRedGreen = has_blue_event(flow.flowchart, checkRedEvent, greenGetEvent)

    tunicBlue = event_tools.createSwitchEvent(flow.flowchart, 'Inventory', 'HasItem', {'count': 1, 'itemType': 20}, {0: getRedBlue, 1: getRedGreen})
    tunicRed = event_tools.createSwitchEvent(flow.flowchart, 'Inventory', 'HasItem', {'count': 1, 'itemType': 19}, {0: tunicBlue, 1: getBlueGreen})

    greeting = event_tools.createActionEvent(flow.flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy7'}, tunicRed)

    event_tools.insertEventAfter(flow.flowchart, 'Telephone', greeting)

    fork = event_tools.findEvent(flow.flowchart, 'Event231')
    fork.data.forks.pop(2) # remove the gethints event

    subFlow = event_tools.createSubFlowEvent(flow.flowchart, '', 'Telephone', {}, 'Event113')
    event_tools.insertEventAfter(flow.flowchart, 'Event98', subFlow)

    return flow



def has_green_event(flowchart, red, blue):
    dialogResult = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult4', {}, {0: red, 1: blue, 2: None})
    return event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy1_2'}, dialogResult)


def has_red_event(flowchart, blue, green):
    dialogResult = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult4', {}, {0: blue, 1: green, 2: None})
    return event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy1_4'}, dialogResult)


def has_blue_event(flowchart, red, green):
    dialogResult = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult4', {}, {0: red, 1: green, 2: None})
    return event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy1_3'}, dialogResult)
