import Tools.event_tools as event_tools
from Randomizers import item_get, data



def writeSwapEvents(flowchart):
    """Makes the telephone pickup event to basically just be the Fairy Queen and lets you swap tunics"""

    # telephone needs dialog query 'GetLastResult4' to get dialog result
    event_tools.addActorQuery(event_tools.findActor(flowchart, 'Dialog'), 'GetLastResult4')

    green_get = item_get.insertItemGetAnimation(flowchart, 'ClothesGreen', -1, None, None)

    red_get = item_get.insertItemGetAnimation(flowchart, 'ClothesRed', -1, None, None)
    check_red = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': data.RED_TUNIC_FOUND_FLAG}, {0: None, 1: red_get})

    blue_get = item_get.insertItemGetAnimation(flowchart, 'ClothesBlue', -1, None, None)
    check_blue = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': data.BLUE_TUNIC_FOUND_FLAG}, {0: None, 1: blue_get})

    get_red_blue = hasGreenEvent(flowchart, check_red, check_blue)
    get_blue_green = hasRedEvent(flowchart, check_blue, green_get)
    get_red_green = hasBlueEvent(flowchart, check_red, green_get)

    tunic_blue = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem', {'count': 1, 'itemType': 20}, {0: get_red_blue, 1: get_red_green})
    tunic_red = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem', {'count': 1, 'itemType': 19}, {0: tunic_blue, 1: get_blue_green})

    greeting = event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy7'}, tunic_red)

    event_tools.insertEventAfter(flowchart, 'Telephone', greeting)

    fork = event_tools.findEvent(flowchart, 'Event231')
    fork.data.forks.pop(2) # remove the gethints event

    sub_flow = event_tools.createSubFlowEvent(flowchart, '', 'Telephone', {}, 'Event113')
    event_tools.insertEventAfter(flowchart, 'Event98', sub_flow)



def hasGreenEvent(flowchart, red, blue):
    """If the player currently has the green tunic, create and return the dialog event for swapping between red and blue"""

    dialog_result = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult4', {}, {0: red, 1: blue, 2: None})
    return event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy1_2'}, dialog_result)


def hasRedEvent(flowchart, blue, green):
    """If the player currently has the red tunic, create and return the dialog event for swapping between blue and green"""

    dialog_result = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult4', {}, {0: blue, 1: green, 2: None})
    return event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy1_4'}, dialog_result)


def hasBlueEvent(flowchart, red, green):
    """If the player currently has the blue tunic, create and return the dialog event for swapping between red and green"""

    dialog_result = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult4', {}, {0: red, 1: green, 2: None})
    return event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy1_3'}, dialog_result)
