import Tools.event_tools as event_tools
from Randomizers import data



def makeStartChanges(flow, placements):
    playerStartFlagsFirstEvent = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag', {'symbol': 'FirstClear', 'value': True})
    playerStartFlagCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': 'FirstClear'}, {0: playerStartFlagsFirstEvent, 1: None})

    playerStartEventFlags = [
        ('EventFlags', 'SetFlag', {'symbol': 'SecondClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'ThirdClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'FourthClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'FifthClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'SixthClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'SeventhClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'NinthClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'TenthClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'EleventhClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'TwelveClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'ThirteenClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'FourteenClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'FiveteenClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'WalrusAwaked', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'MarinRescueClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'MamuMazeClear', 'value': True}),
        ('EventFlags', 'SetFlag', {'symbol': 'StickDrop', 'value': True}), # flag for the bridge, we make kiki use another flag
    ]
    if placements['settings']['open-kanalet']:
        playerStartEventFlags.append(('EventFlags', 'SetFlag', {'symbol': 'GateOpen_Switch_KanaletCastle_01B', 'value': True}))
    
    if not placements['settings']['shuffle-tunics']:
        playerStartEventFlags.append(('EventFlags', 'SetFlag', {'symbol': data.RED_TUNIC_FOUND_FLAG, 'value': True}))
        playerStartEventFlags.append(('EventFlags', 'SetFlag', {'symbol': data.BLUE_TUNIC_FOUND_FLAG, 'value': True}))
    
    event_tools.insertEventAfter(flow.flowchart, 'Event558', playerStartFlagCheckEvent)
    event_tools.createActionChain(flow.flowchart, playerStartFlagsFirstEvent, playerStartEventFlags)

    # Remove the part that kills the rooster after D7 in Level7DungeonIn_FlyingCucco
    event_tools.insertEventAfter(flow.flowchart, 'Level7DungeonIn_FlyingCucco', 'Event476')
    
    if placements['settings']['fast-stealing']:
        # Remove the flag that says you stole so that the shopkeeper won't kill you
        event_tools.createActionChain(flow.flowchart, 'Event774', [
            ('EventFlags', 'SetFlag', {'symbol': 'StealSuccess', 'value': False})
        ])
