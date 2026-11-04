import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import item_get



def makeEventChanges(flowchart, placements, item_defs):
    change_defs = [
        ('fishing-orange', 'Event113', 'Event212'),
        ('fishing-cheep-cheep', 'Event3', 'Event10'),
        ('fishing-ol-baron', 'Event133', 'Event140'),
        ('fishing-50', 'Event182', 'Event240'),
        ('fishing-100', 'Event191', 'Event247'),
        ('fishing-150', 'Event193', 'Event255'),
        ('fishing-loose', 'Event264', 'Event265')
    ]

    for defs in change_defs:
        item_key = item_defs[placements[defs[0]]]['item-key']
        item_index = placements['indexes'][defs[0]] if defs[0] in placements['indexes'] else -1
        item_get.insertItemGetAnimation(flowchart, item_key, item_index, defs[1], defs[2], False, False)
    
    bottle_get = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': 'FishingBottleGet', 'value': True}, 'Event264')

    event_tools.insertEventAfter(flowchart, 'Event20', 'Event3')
    event_tools.insertEventAfter(flowchart, 'Event18', 'Event133')
    event_tools.insertEventAfter(flowchart, 'Event24', 'Event191')
    event_tools.insertEventAfter(flowchart, 'FishingGetBottle', bottle_get)



def fixFishingBottle(flowchart):
    # since no event actually removes sword, we change itemType 0 in RemoveItem to remove Bottle 1 with ASM
    take_bottle = event_tools.createActionEvent(flowchart, 'Inventory', 'RemoveItem',
        {'itemType': 0}, 'Event74')
    fishing_bottle_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'FishingBottleGet'}, {0: take_bottle, 1: 'Event83'})

    event_tools.insertEventAfter(flowchart, 'Event83', 'Event74')
    event_tools.insertEventAfter(flowchart, 'Event315', fishing_bottle_check)
    event_tools.insertEventAfter(flowchart, 'Event316', fishing_bottle_check)
    event_tools.insertEventAfter(flowchart, 'Event317', fishing_bottle_check)

    give_bottle = event_tools.createActionEvent(flowchart, 'Inventory', 'AddBottle',
        {'index': 1}, 'Event45')
    take_bottle_2 = event_tools.createActionEvent(flowchart, 'Inventory', 'RemoveItem',
        {'itemType': 0}, 'Event45')
    bottle2_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'Bottle2Get'}, {0: take_bottle_2, 1: give_bottle})

    event_tools.insertEventAfter(flowchart, 'Event189', bottle2_check)
