import Tools.event_tools as event_tools
from Randomizers import item_get



def writeKeyEvent(flowchart, item_key, item_index, room):
    """Adds a new entry point to the SmallKey event flow for each key room, and inserts an ItemGetAnimation to it"""
    
    # If item is SmallKey/NightmareKey/Map/Compass/Beak/Rupee, add to inventory without any pickup animation
    if item_key[:3] in ['Sma', 'Nig', 'Dun', 'Com', 'Sto', 'Rup']:
        item_event = event_tools.createActionChain(flowchart, None, [
            ('Inventory', 'AddItemByKey', {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
        ], None)
    else:
        item_event = item_get.insertItemGetAnimation(flowchart, item_key, item_index)

    event_tools.addEntryPoint(flowchart, room)

    event_tools.createActionChain(flowchart, room, [
        ('SmallKey', 'Deactivate', {}),
        ('SmallKey', 'SetActorSwitch', {'value': True, 'switchIndex': 1}),
        ('SmallKey', 'Destroy', {})
    ], item_event)



def makeKeysFaster(flowchart):
    '''Gives control back to the player after triggering the key to fall'''
    
    event_tools.insertEventAfter(flowchart, 'pop', 'Event5')
    event_tools.insertEventAfter(flowchart, 'Event2', None)

    # removed due to the possibility of collecting this key before it falls with the use of glitches
    # event_tools.insertEventAfter(flowchart, 'Lv4_04E_pop', 'Event7')
    # event_tools.insertEventAfter(flowchart, 'Event1', None)



# def writeSunkenKeyEvent(flowchart):
#     event_tools.addEntryPoint(flowchart, 'Lv4_04E_pop')

#     event_tools.createActionChain(flowchart, 'Lv4_04E_pop', [
#         ('GoldenLeaf', 'GenericGimmickSequence', {'cameraLookAt': True, 'distanceOffset': 0.0}),
#         ('GoldenLeaf', 'Activate', {}),
#         ('GoldenLeaf', 'PlayOneshotSE', {'label': 'SE_SY_NAZOKAGI_DROP', 'pitch': 1.0, 'volume': 1.0}),
#         ('GoldenLeaf', 'Fall', {}),
#         ('Timer', 'Wait', {'time': 2}),
#         ('Audio', 'PlayJingle', {'label': 'BGM_NAZOTOKI_SEIKAI', 'volume': 1.0}),
#         ('GoldenLeaf', 'Destroy', {})
#     ])