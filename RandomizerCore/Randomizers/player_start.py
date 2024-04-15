import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import data



def makeStartChanges(flowchart, settings):
    """Sets a bunch of flags when you leave the house for the first time, 
    including Owl cutscenes watched, Walrus Awakened, and some flags specific to settings"""

    player_start_flags_first_event = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': 'FirstClear', 'value': True})
    player_start_flag_check_event = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
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
        ('EventFlags', 'SetFlag', {'symbol': 'SwordGet', 'value': True}), # flag for woods owl, the sinking sword's flag is changed
        ('EventFlags', 'SetFlag', {'symbol': 'UI_FieldMapTraverse_MabeVillage', 'value': True}), # temp fix
    ]

    if settings['open-kanalet']:
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'GateOpen_Switch_KanaletCastle_01B', 'value': True}))
    
    if settings['open-bridge']: # flag for the bridge, we make kiki use another flag
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'StickDrop', 'value': True}))
    
    if settings['open-mamu']:
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'MamuMazeClear', 'value': True}))
    
    if not settings['shuffle-bombs'] and settings['unlocked-bombs']:
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': data.BOMBS_FOUND_FLAG, 'value': True}))
    
    if settings['randomize-enemies']: # special case where we need stairs under armos to be visible and open
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'AppearStairsFld10N', 'value': True}))
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'AppearStairsFld11O', 'value': True}))
    
    if settings['fast-stalfos']: # set the door open flags for the first 3 master stalfos fights to be true
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'DoorOpen_Btl1_L05_05F', 'value': True}))
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'DoorOpen_Btl2_L05_04H', 'value': True}))
        player_start_event_flags.append(('EventFlags', 'SetFlag', {'symbol': 'DoorOpen_Btl3_L05_01F', 'value': True}))

    event_tools.insertEventAfter(flowchart, 'Event558', player_start_flag_check_event)
    event_tools.createActionChain(flowchart, player_start_flags_first_event, player_start_event_flags)

    # Remove the part that kills the rooster after D7 in Level7DungeonIn_FlyingCucco
    event_tools.insertEventAfter(flowchart, 'Level7DungeonIn_FlyingCucco', 'Event476')
    
    if settings['fast-stealing']:
        # Remove the flag that says you stole so that the shopkeeper won't kill you
        event_tools.createActionChain(flowchart, 'Event774', [
            ('EventFlags', 'SetFlag', {'symbol': 'StealSuccess', 'value': False})
        ])
    
    # Remove the 7 second timeOut wait on the companion when it gets blocked from a loading zone
    timeout_events = ('Event637', 'Event660', 'Event693', 'Event696', 'Event371', 'Event407', 'Event478')
    for e in timeout_events:
        event_tools.findEvent(flowchart, e).data.params.data['timeOut'] = 0.0
    
    # # Tests to try to make companions work inside dungeons
    # companion_follow = event_tools.createSubFlowEvent(flowchart, '', 'NPC_Out_Field', {}, 'Event8')
    # event_tools.insertEventAfter(flowchart, 'Event6', companion_follow)
