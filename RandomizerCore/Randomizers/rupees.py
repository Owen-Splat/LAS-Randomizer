import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import item_get



def makeEventChanges(flowchart, rup_index, item_key, item_index):
    """Adds an entry point to the flowchart for each rupee, and inserts the ItemGetAnimation event into it"""
    
    event_tools.addEntryPoint(flowchart, f'Lv10Rupee_{rup_index + 1}')

    # If item is SmallKey/NightmareKey/Map/Compass/Beak/Rupee, add to inventory without any pickup animation
    if item_key[:3] in ['Sma', 'Nig', 'Dun', 'Com', 'Sto', 'Rup']:
        get_anim = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey',
        {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
    else:
        get_anim = item_get.insertItemGetAnimation(flowchart, item_key, item_index)

    event_tools.createActionChain(flowchart, f'Lv10Rupee_{rup_index + 1}', [
        ('SinkingSword', 'Destroy', {}),
        ('EventFlags', 'SetFlag', {'symbol': 'Lv10RupeeGet' if rup_index == 0 else f'Lv10RupeeGet_{rup_index + 1}', 'value': True})
    ], get_anim)
