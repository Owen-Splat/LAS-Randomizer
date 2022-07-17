import Tools.event_tools as event_tools
from Randomizers import item_get, data



def writeSwapEvents(flowchart):
    """Makes the telephone pickup event to basically just be the Fairy Queen and lets you swap tunics"""

    # telephone needs dialog query 'GetLastResult4' to get dialog result
    event_tools.addActorQuery(event_tools.findActor(flowchart, 'Dialog'), 'GetLastResult4')

    greenGet = item_get.insertItemGetAnimation(flowchart, 'ClothesGreen', -1, None, None)

    redGet = item_get.insertItemGetAnimation(flowchart, 'ClothesRed', -1, None, None)
    checkRed = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': data.RED_TUNIC_FOUND_FLAG}, {0: None, 1: redGet})

    blueGet = item_get.insertItemGetAnimation(flowchart, 'ClothesBlue', -1, None, None)
    checkBlue = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
    {'symbol': data.BLUE_TUNIC_FOUND_FLAG}, {0: None, 1: blueGet})

    getRedBlue = hasGreenEvent(flowchart, checkRed, checkBlue)
    getBlueGreen = hasRedEvent(flowchart, checkBlue, greenGet)
    getRedGreen = hasBlueEvent(flowchart, checkRed, greenGet)

    tunicBlue = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem', {'count': 1, 'itemType': 20}, {0: getRedBlue, 1: getRedGreen})
    tunicRed = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem', {'count': 1, 'itemType': 19}, {0: tunicBlue, 1: getBlueGreen})

    greeting = event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy7'}, tunicRed)

    event_tools.insertEventAfter(flowchart, 'Telephone', greeting)

    fork = event_tools.findEvent(flowchart, 'Event231')
    fork.data.forks.pop(2) # remove the gethints event

    subFlow = event_tools.createSubFlowEvent(flowchart, '', 'Telephone', {}, 'Event113')
    event_tools.insertEventAfter(flowchart, 'Event98', subFlow)



def hasGreenEvent(flowchart, red, blue):
    """If the player currently has the green tunic, create and return the dialog event for swapping between red and blue"""

    dialogResult = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult4', {}, {0: red, 1: blue, 2: None})
    return event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy1_2'}, dialogResult)


def hasRedEvent(flowchart, blue, green):
    """If the player currently has the red tunic, create and return the dialog event for swapping between blue and green"""

    dialogResult = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult4', {}, {0: blue, 1: green, 2: None})
    return event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy1_4'}, dialogResult)


def hasBlueEvent(flowchart, red, green):
    """If the player currently has the blue tunic, create and return the dialog event for swapping between red and green"""

    dialogResult = event_tools.createSwitchEvent(flowchart, 'Dialog', 'GetLastResult4', {}, {0: red, 1: green, 2: None})
    return event_tools.createActionEvent(flowchart, 'Telephone', 'Examine', {'message': 'SubEvent:QuestGrandFairy1_3'}, dialogResult)
