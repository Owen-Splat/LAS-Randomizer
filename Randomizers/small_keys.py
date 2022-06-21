import Tools.event_tools as event_tools
from Randomizers import item_get



def writeKeyEvent(flowchart, itemKey, itemIndex, room):
    # If item is SmallKey/NightmareKey/Map/Compass/Beak/Rupee, add to inventory without any pickup animation
    if itemKey[:3] in ['Sma', 'Nig', 'Dun', 'Com', 'Sto', 'Rup']:
        itemEvent = event_tools.createActionChain(flowchart, None, [
            ('Inventory', 'AddItemByKey', {'itemKey': itemKey, 'count': 1, 'index': itemIndex, 'autoEquip': False})
        ], None)
    else:
        itemEvent = item_get.insertItemGetAnimation(flowchart, itemKey, itemIndex)

    event_tools.addEntryPoint(flowchart, room)

    event_tools.createActionChain(flowchart, room, [
        ('SmallKey', 'Deactivate', {}),
        ('SmallKey', 'SetActorSwitch', {'value': True, 'switchIndex': 1}),
        ('SmallKey', 'Destroy', {})
    ], itemEvent)
