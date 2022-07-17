import Tools.event_tools as event_tools



def makeEventChanges(flow, placements):
    """Edits Tarin to detain you based on if you talked to him rather than on having shield"""
    
    # If reduce-farming is on, and Tarin has boots, also give 20 bombs if Tarin has boots
    if placements['tarin'] == 'boots' and placements['settings']['reduce-farming'] and not placements['settings']['shuffle-bombs']:
        event_tools.createActionChain(flow.flowchart, 'Event31', [
            ('Inventory', 'AddItemByKey', {'itemKey': 'Bomb', 'count': 20, 'index': -1, 'autoEquip': False})
            ], 'Event2')

    event0 = event_tools.findEvent(flow.flowchart, 'Event0')
    event78 = event_tools.findEvent(flow.flowchart, 'Event78')
    event0.data.actor = event78.data.actor
    event0.data.actor_query = event78.data.actor_query
    event0.data.params = event78.data.params
    
    """eventtools.createActionChain(flow.flowchart, 'Event36', [
        ('Inventory', 'AddItemByKey', {'itemKey': 'SwordLv1', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'Shield', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'PegasusBoots', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'PowerBraceletLv1', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'PowerBraceletLv2', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'Song_Soul', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'Song_WindFish', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'Ocarina', 'count': 1, 'index': -1, 'autoEquip': True}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'RocsFeather', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'HookShot', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'Boomerang', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'Flippers', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'TailKey', 'count': 1, 'index': -1, 'autoEquip': False}),
        #('Inventory', 'AddItemByKey', {'itemKey': 'Bomb', 'count': 30, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'MagicPowder', 'count': 10, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'Rupee300', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('Inventory', 'AddItemByKey', {'itemKey': 'ShellRader', 'count': 1, 'index': -1, 'autoEquip': False}),
        ('EventFlags', 'SetFlag', {'symbol': 'MamuMazeClear', 'value': True})
        ], 'Event52')"""
