import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import data


class PlayerStartEventFixes:
    """Sets a bunch of flags for cutscenes being watched/triggered to prevent them from ever happening"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        flow = self.parent.file_manager.readFile('PlayerStart.bfevfl')
        self.giveStartingItems(flow.flowchart)
        self.makeStartChanges(flow.flowchart)

        # skip over BGM_HOUSE_FIRST when Link wakes up because it overlaps with the shuffled zone BGM
        if self.parent.settings["Music"] != "Vanilla":
            event_tools.insertEventAfter(flow.flowchart, 'Event150', 'Event151')

        self.parent.file_manager.writeFile('PlayerStart.bfevfl', flow)


    def giveStartingItems(self, flowchart) -> None:
        """We want to give the items when Link wakes up for the first time instead of talking to Tarin

        This is setting the groundwork for random starting area"""

        before_event = "Event151"
        after_event = "Event155"
        event_defs = []
        sword_num = 0
        shield_num = 0
        bracelet_num = 0

        # starting items
        for i in self.parent.placements['starting-items']:
            item_key = self.parent.item_defs[i]['item-key']

            if item_key == 'SwordLv1':
                sword_num += 1
                if sword_num == 2:
                    item_key = 'SwordLv2'

            elif item_key == 'Shield':
                shield_num += 1
                if shield_num == 2:
                    item_key = 'MirrorShield'

            elif item_key == 'PowerBraceletLv1':
                bracelet_num += 1
                if bracelet_num == 2:
                    item_key = 'PowerBraceletLv2'

            event_defs += self.parent.item_get_manager.getWithoutAnimation(item_key, -1)

        # starting dungeon items
        # we have hooked custom code to read the index as the dungeon in the Inventory::AddItemID function
        if self.parent.settings["Dungeon Maps"] == "Start With":
            for i in range(10):
                if i == 8: # panel dungeon index, ignore
                    continue
                event_defs += self.parent.item_get_manager.getWithoutAnimation("DungeonMap", i)
        if self.parent.settings["Compasses"] == "Start With":
            for i in range(10):
                if i == 8: # panel dungeon index, ignore
                    continue
                event_defs += self.parent.item_get_manager.getWithoutAnimation("Compass", i)
        if self.parent.settings["Stone Beaks"] == "Start With":
            for i in range(10):
                if i == 8: # panel dungeon index, ignore
                    continue
                event_defs += self.parent.item_get_manager.getWithoutAnimation("StoneBeak", i)
        if self.parent.settings["Small Keys"] == "Start With":
            for i in range(10):
                if i == 8: # panel dungeon index, ignore
                    continue
                for c in range(DUNGEON_KEY_COUNTS[i]):
                    event_defs += self.parent.item_get_manager.getWithoutAnimation("SmallKey", i)
        if self.parent.settings["Nightmare Keys"] == "Start With":
            for i in range(10):
                if i == 8: # panel dungeon index, ignore
                    continue
                event_defs += self.parent.item_get_manager.getWithoutAnimation("NightmareKey", i)

        # heart pieces and containers
        for i in range(self.parent.settings["Pieces"]):
            event_defs += self.parent.item_get_manager.getWithoutAnimation("HeartPiece", i)
        for i in range(self.parent.settings["Containers"]):
            event_defs += self.parent.item_get_manager.getWithoutAnimation("HeartContainer", i)

        # starting rupees
        starting_rupees = self.parent.settings["Rupees"]
        if starting_rupees > 0:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'AddRupee')
            after_event = event_tools.createActionEvent(flowchart, 'Link', 'AddRupee', {'amount': starting_rupees}, after_event)

        if len(event_defs) > 0:
            event_tools.createActionChain(flowchart, before_event, event_defs, after_event)
        else:
            event_tools.insertEventAfter(flowchart, before_event, after_event)


    # this stuff can just go with the starting items when I get around to making random starting area
    def makeStartChanges(self, flowchart) -> None:
        """Sets a bunch of flags when you leave the house for the first time, 
        including Owl cutscenes watched, Walrus Awakened, and some flags specific to settings"""

        player_start_flags_first_event = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'FirstClear', 'value': True})
        player_start_flag_check_event = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'FirstClear'}, {0: player_start_flags_first_event, 1: None})

        player_start_event_flags = list(START_FLAGS)

        if self.parent.settings["Open Kanalet"]:
            player_start_event_flags.append('GateOpen_Switch_KanaletCastle_01B')

        if self.parent.settings["Completed Bridge"]: # flag for the bridge, we make kiki use another flag
            player_start_event_flags.append('StickDrop')

        if self.parent.settings["Open Mamu"]:
            player_start_event_flags.append('MamuMazeClear')

        # dont set bombs found flag, shop shouldnt sell any until you find some
        # without shuffled bombs, this just means you can get them from any natural source
        # if not self.parent.settings["Shuffled Bombs"]:
        #     player_start_event_flags.append(self.parent.flag_manager.flags["BombsFoundFlag"])

        if self.parent.settings["Randomize Enemies"]: # special case where we need stairs under armos to be visible and open
            player_start_event_flags.append('AppearStairsFld10N')
            player_start_event_flags.append('AppearStairsFld11O')

        if self.parent.settings["Fast Stalfos"]: # set the door open flags for the first 3 master stalfos fights to be true
            player_start_event_flags.append('DoorOpen_Btl1_L05_05F')
            player_start_event_flags.append('DoorOpen_Btl2_L05_04H')
            player_start_event_flags.append('DoorOpen_Btl3_L05_01F')

        if self.parent.settings["Boss Cutscenes"]: # set boss cutscenes to have already been watched
            player_start_event_flags.extend(BOSS_FLAGS)
        # if settings['nag-meesages']: # set annoying one-time messages to not pop-up
        #     player_start_event_flags.extend(MESSAGE_FLAGS)

        player_start_event_flags = [('EventFlags', 'SetFlag', {'symbol': f, 'value': True}) for f in player_start_event_flags]

        event_tools.insertEventAfter(flowchart, 'Event558', player_start_flag_check_event)
        event_tools.createActionChain(flowchart, player_start_flags_first_event, player_start_event_flags)

        # Remove the part that kills the rooster after D7 in Level7DungeonIn_FlyingCucco
        event_tools.insertEventAfter(flowchart, 'Level7DungeonIn_FlyingCucco', 'Event476')

        # Remove the 7 second timeOut wait on the companion when it gets blocked from a loading zone
        timeout_events = ('Event637', 'Event660', 'Event693', 'Event696', 'Event371', 'Event407', 'Event478')
        for e in timeout_events:
            event_tools.findEvent(flowchart, e).data.params.data['timeOut'] = 0.0


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
    'UI_FieldMapTraverse_MabeVillage', # mabe wont be cleared on the map if it starts in the bowwow-stolen phase
    # figured it out, this phase uses a different zoneID which means I need to make a new entry in UiFieldMapMask.gsheet
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

DUNGEON_KEY_COUNTS = {
    0: 3,
    1: 5,
    2: 9,
    3: 5,
    4: 3,
    5: 3,
    6: 3,
    7: 7,
    9: 3
}
