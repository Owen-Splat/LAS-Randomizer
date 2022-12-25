import Tools.event_tools as event_tools
from Randomizers import actors, item_get



def makeEventChanges(flowchart, placements, item_defs):
    """Edits Tarin to detain you based on if you talked to him rather than on having shield"""
    
    item_index = placements['indexes']['tarin'] if 'tarin' in placements['indexes'] else -1
    item_get.insertItemGetAnimation(flowchart, item_defs[placements['tarin']]['item-key'], item_index, 'Event52', 'Event31')

    # If reduce-farming is on, and Tarin has boots, also give 20 bombs if Tarin has boots
    # and not placements['settings']['shuffle-bombs']
    if placements['tarin'] == 'boots' and placements['settings']['reduce-farming']:
        event_tools.createActionChain(flowchart, 'Event31', [
            ('Inventory', 'AddItemByKey', {'itemKey': 'Bomb', 'count': 20, 'index': -1, 'autoEquip': False})
        ], 'Event2')

    event0 = event_tools.findEvent(flowchart, 'Event0')
    event78 = event_tools.findEvent(flowchart, 'Event78')
    event0.data.actor = event78.data.actor
    event0.data.actor_query = event78.data.actor_query
    event0.data.params = event78.data.params
    
    if len(placements['starting-instruments']) > 0:
        event_defs = []
        for inst in placements['starting-instruments']:
            event_defs.append(('Inventory', 'AddItemByKey', {'itemKey': item_defs[inst]['item-key'], 'count': 1, 'index': -1, 'autoEquip': False}))

            if inst == 'surf-harp': # set ghost clear flags if getting harp
                event_defs += [
                    ('EventFlags', 'SetFlag', {'symbol': 'GhostClear1', 'value': True}),
                    ('EventFlags', 'SetFlag', {'symbol': 'Ghost2_Clear', 'value': True}),
                    ('EventFlags', 'SetFlag', {'symbol': 'Ghost3_Clear', 'value': True}),
                    ('EventFlags', 'SetFlag', {'symbol': 'Ghost4_Clear', 'value': True})
                ]
                continue

            if inst == 'full-moon-cello': # close the moblin cave doors so the moblins appear
                event_defs += [
                    ('EventFlags', 'SetFlag', {'symbol': 'BowWowEvent', 'value': True}),
                    ('EventFlags', 'SetFlag', {'symbol': 'DoorOpen_Btl_MoriblinCave_2A', 'value': False}),
                    ('EventFlags', 'SetFlag', {'symbol': 'DoorOpen_Btl_MoriblinCave_1A', 'value': False})
                ]
        event_tools.createActionChain(flowchart, 'Event36', event_defs, 'Event52')
    
    # event_tools.createActionChain(flowchart, 'Event36', [
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'SwordLv1', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'Shield', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'PegasusBoots', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'PowerBraceletLv1', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'PowerBraceletLv2', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'Song_Soul', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'Song_WindFish', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'Ocarina', 'count': 1, 'index': -1, 'autoEquip': True}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'RocsFeather', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'HookShot', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'Boomerang', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'Flippers', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'TailKey', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     #('Inventory', 'AddItemByKey', {'itemKey': 'Bomb', 'count': 30, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'MagicPowder', 'count': 10, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'Rupee300', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('Inventory', 'AddItemByKey', {'itemKey': 'ShellRader', 'count': 1, 'index': -1, 'autoEquip': False}),
    #     ('EventFlags', 'SetFlag', {'symbol': 'MamuMazeClear', 'value': True})
    #     ], 'Event52')
