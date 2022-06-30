import Tools.event_tools as event_tools
from Randomizers import item_get



def makeEventChanges(flowchart, rupIndex, itemKey, itemIndex):
    event_tools.addEntryPoint(flowchart, f'Lv10Rupee_{rupIndex + 1}')

    # If item is SmallKey/NightmareKey/Map/Compass/Beak/Rupee, add to inventory without any pickup animation
    if itemKey[:3] in ['Sma', 'Nig', 'Dun', 'Com', 'Sto', 'Rup']:
        itemGet = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
        {'itemKey': itemKey, 'count': 1, 'index': itemIndex, 'autoEquip': False})
    else:
        itemGet = item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex)

    event_tools.createActionChain(flowchart, f'Lv10Rupee_{rupIndex + 1}', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': 'Lv10RupeeGet' if rupIndex == 0 else f'Lv10RupeeGet_{rupIndex + 1}', 'value': True})
    ], itemGet)
