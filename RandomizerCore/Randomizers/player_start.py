import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import data, item_get

START_FLAGS = (
    'FirstClear',
    'SecondClear',
    'ThirdClear',
    'FourthClear',
    'FifthClear',
    'SixthClear',
    'SeventhClear',
    'NinthClear',
    'TenthClear',
    'EleventhClear',
    'TwelveClear',
    'ThirteenClear',
    'FourteenClear',
    'FiveteenClear',
    'WalrusAwaked',
    'MarinRescueClear',
    'SwordGet',
    'UI_FieldMapTraverse_MabeVillage', # mabe wont be cleared on the map when you have bowwow for some reason
)

BOSS_FLAGS = (
    'Lv1BossDemoClear',
    'Lv2BossDemoClear',
    'Lv3BossDemoClear',
    'Lv4BossDemoClear',
    'Lv5BossDemoClear',
    'Lv05BrokeWall1',
    'Lv05BrokeWall2',
    'Lv05BrokeWall3',
    'Lv05BrokeWall4',
    'Lv05BrokeFloor',
    'Lv6BossDemoClear',
    'Lv7BossDemoClear',
    'Lv8BossDemoClear',
    'Lv9BossDemoClear',
    'ShadowBattle',
    'LanmolaDemoClear',
    'GrimCreeperDemoClear',
    'StoneHinoxDemoClear',
    'GiantBuzzBlobDemoClear',
    'EvilOrbDemoClear',
    'DeguArmosDemoClear',
    'LanemoraDemoClear'
)

MESSAGE_FLAGS = (
    # 'FindWarpPedestalFirst', # excluded because it forces you into the warp
    'FindWarpPointFirst',
    'ArrowGetNoBowMessageShown',
    'MagicPowderFirstMessage',
    'SmallKeyFirstGet'
)


def makeStartChanges(flowchart, settings):
    """Sets a bunch of flags when you leave the house for the first time, 
    including Owl cutscenes watched, Walrus Awakened, and some flags specific to settings"""

    player_start_flags_first_event = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
        {'symbol': 'FirstClear', 'value': True})
    player_start_flag_check_event = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'FirstClear'}, {0: player_start_flags_first_event, 1: None})

    player_start_event_flags = list(START_FLAGS)

    if settings['open-kanalet']:
        player_start_event_flags.append('GateOpen_Switch_KanaletCastle_01B')
    
    if settings['open-bridge']: # flag for the bridge, we make kiki use another flag
        player_start_event_flags.append('StickDrop')
    
    if settings['open-mamu']:
        player_start_event_flags.append('MamuMazeClear')
    
    if not settings['shuffle-bombs'] and settings['unlocked-bombs']:
        player_start_event_flags.append(data.BOMBS_FOUND_FLAG)
    
    if settings['randomize-enemies']: # special case where we need stairs under armos to be visible and open
        player_start_event_flags.append('AppearStairsFld10N')
        player_start_event_flags.append('AppearStairsFld11O')
    
    if settings['fast-stalfos']: # set the door open flags for the first 3 master stalfos fights to be true
        player_start_event_flags.append('DoorOpen_Btl1_L05_05F')
        player_start_event_flags.append('DoorOpen_Btl2_L05_04H')
        player_start_event_flags.append('DoorOpen_Btl3_L05_01F')
    
    if settings['boss-cutscenes']: # set boss cutscenes to have already been watched
        player_start_event_flags.extend(BOSS_FLAGS)
    # if settings['nag-meesages']: # set annoying one-time messages to not pop-up
    #     player_start_event_flags.extend(MESSAGE_FLAGS)
    
    player_start_event_flags = [('EventFlags', 'SetFlag', {'symbol': f, 'value': True}) for f in player_start_event_flags]

    event_tools.insertEventAfter(flowchart, 'Event558', player_start_flag_check_event)
    event_tools.createActionChain(flowchart, player_start_flags_first_event, player_start_event_flags)

    # Remove the part that kills the rooster after D7 in Level7DungeonIn_FlyingCucco
    event_tools.insertEventAfter(flowchart, 'Level7DungeonIn_FlyingCucco', 'Event476')
    
    if settings['fast-stealing']:
        # Remove the flag that says you stole so that the shopkeeper won't kill you
        event_tools.createActionChain(flowchart, 'Event774', [
            ('EventFlags', 'SetFlag', {'symbol': 'StealSuccess', 'value': False})
        ])

    # Auto give dungeon items when entering the dungeon (We have to do that for the level to be identified properly)
    dungeon_item_setting = settings['dungeon-items']
    if dungeon_item_setting != 'none':
        event_defs = []

        if dungeon_item_setting in ['mc', 'mcb']:
            event_defs += item_get.insertItemWithoutAnimation('DungeonMap', -1)
            event_defs += item_get.insertItemWithoutAnimation('Compass', -1)

        if dungeon_item_setting in ['stone-beak', 'mcb']:
            event_defs += item_get.insertItemWithoutAnimation('StoneBeak', -1)

        # Adding event on DungeonIn entrypoint
        event_tools.createActionChain(flowchart, 'Event539', event_defs)

    # Remove the 7 second timeOut wait on the companion when it gets blocked from a loading zone
    timeout_events = ('Event637', 'Event660', 'Event693', 'Event696', 'Event371', 'Event407', 'Event478')
    for e in timeout_events:
        event_tools.findEvent(flowchart, e).data.params.data['timeOut'] = 0.0
