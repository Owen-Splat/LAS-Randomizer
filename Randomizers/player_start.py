import Tools.event_tools as event_tools
from Randomizers import data



def makeStartChanges(flow, settings):
    """Sets a bunch of flags when you leave the house for the first time, 
    including Owl cutscenes watched, Walrus Awakened, and some flags specific to settings"""

    player_start_flags_first_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
        {'symbol': 'FirstClear', 'value': True})
    player_start_flag_check_event = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'FirstClear'}, {0: player_start_flags_first_event, 1: None})

    player_start_event_flags = [
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
    ]

    if settings['open-kanalet']:
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'GateOpen_Switch_KanaletCastle_01B', 'value': True}))
    
    if settings['open-bridge']: # flag for the bridge, we make kiki use another flag
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'StickDrop', 'value': True}))
    
    if settings['open-mamu']:
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'MamuMazeClear', 'value': True}))
    
    if not settings['shuffle-tunics']:
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': data.RED_TUNIC_FOUND_FLAG, 'value': True}))
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': data.BLUE_TUNIC_FOUND_FLAG, 'value': True}))
    
    if not settings['shuffle-bombs'] and settings['unlocked-bombs']:
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': data.BOMBS_FOUND_FLAG, 'value': True}))
    
    event_tools.insertEventAfter(flow.flowchart, 'Event558', player_start_flag_check_event)
    event_tools.createActionChain(flow.flowchart, player_start_flags_first_event, player_start_event_flags)

    # Remove the part that kills the rooster after D7 in Level7DungeonIn_FlyingCucco
    event_tools.insertEventAfter(flow.flowchart, 'Level7DungeonIn_FlyingCucco', 'Event476')
    
    if settings['fast-stealing']:
        # Remove the flag that says you stole so that the shopkeeper won't kill you
        event_tools.createActionChain(flow.flowchart, 'Event774', [
            ('EventFlags', 'SetFlag', {'symbol': 'StealSuccess', 'value': False})
        ])
