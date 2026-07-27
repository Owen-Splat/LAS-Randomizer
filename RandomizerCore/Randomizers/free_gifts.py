import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers.data import DUNGEON_ENTRANCES
import re


class FreeGiftsRandomizer:
    """Handles placing items at NPCs. Some other fixes may be included"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        if self.parent.thread_active: self.walrusChanges()
        if self.parent.thread_active: self.ghostRewardChanges()
        if self.parent.thread_active: self.marinChanges()
        if self.parent.thread_active: self.manboChanges()
        if self.parent.thread_active: self.mamuChanges()
        if self.parent.thread_active: self.madBatterChanges()
        if self.parent.thread_active: self.clothesFairyChanges()
        if self.parent.thread_active: self.invisibleZoraChanges()
        if self.parent.thread_active: self.goriyaChanges()
        if self.parent.thread_active: self.syrupChanges()


    def walrusChanges(self):
        flow = self.parent.file_manager.readFile('Walrus.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'walrus', 'Event53', 'Event110', True)
        self.parent.file_manager.writeFile('Walrus.bfevfl', flow)


    def ghostRewardChanges(self):
        flow = self.parent.file_manager.readFile('Owl.bfevfl')
        new = event_tools.createActionEvent(flow.flowchart, 'Owl', 'Destroy', {})
        self.parent.item_get_manager.get(flow.flowchart, 'ghost-reward', 'Event34', new, True)
        self.parent.file_manager.writeFile('Owl.bfevfl', flow)


    def marinChanges(self):
        flow = self.parent.file_manager.readFile('Marin.bfevfl')

        if self.parent.settings["Song Cutscenes"]: # skip the cutscene if fast-songs is enabled, and make Link sad about it
            sad_face = event_tools.createActionEvent(flow.flowchart, 'Link', 'SetFacialExpression',
                {'expression': 'sad'}, None)
            flag_set = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
                {'symbol': 'MarinsongGet', 'value': True}, sad_face)
            event_tools.insertEventAfter(flow.flowchart, 'Event92', flag_set)
            self.parent.item_get_manager.get(flow.flowchart, 'marin', sad_face, 'Event666', True)
        else:
            self.parent.item_get_manager.get(flow.flowchart, 'marin', 'Event246', 'Event666', True)

        # Remove the event that gives Ballad and edits other events to check if you got the 'song'
        fork = event_tools.findEvent(flow.flowchart, 'Event249')
        fork.data.forks.pop(0)
        event_tools.insertEventAfter(flow.flowchart, 'Event27', 'Event249')
        event20 = event_tools.findEvent(flow.flowchart, 'Event20')
        event160 = event_tools.findEvent(flow.flowchart, 'Event160')
        event676 = event_tools.findEvent(flow.flowchart, 'Event676')
        event160.data.actor = event20.data.actor
        event676.data.actor = event20.data.actor
        event160.data.actor_query = event20.data.actor_query
        event676.data.actor_query = event20.data.actor_query
        event160.data.params.data['symbol'] = 'MarinsongGet'
        event676.data.params.data['symbol'] = 'MarinsongGet'

        # Make Marin not do beach_talk under any circumstance
        event_tools.setSwitchEventCase(flow.flowchart, 'Event21', 0, 'Event674')

        # Remove checking for beach item to get song
        event_tools.setSwitchEventCase(flow.flowchart, 'Event2', 1, 'Event21')

        self.parent.file_manager.writeFile('Marin.bfevfl', flow)


    def manboChanges(self):
        flow = self.parent.file_manager.readFile('ManboTamegoro.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': "ManboItemGetFlag", 'value': True}, 'Event13')

        if self.parent.settings["Song Cutscenes"]: # skip the cutscene if fast-songs is enabled
            before_item = 'Event44'
        else:
            before_item = 'Event31'

        self.parent.item_get_manager.get(flow.flowchart, 'manbo', before_item, flag_event, True)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': "ManboItemGetFlag"}, {0: 'Event37', 1: 'Event35'})
        event_tools.insertEventAfter(flow.flowchart, 'Event9', flag_check)

        self.parent.file_manager.writeFile('ManboTamegoro.bfevfl', flow)


    def mamuChanges(self):
        flow = self.parent.file_manager.readFile('Mamu.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': "MamuItemGetFlag", 'value': True}, 'Event40')

        if self.parent.settings["Song Cutscenes"]: # skip the cutscene if fast-songs is enabled
            before_item = 'Event55'
        else:
            before_item = 'Event85'

        self.parent.item_get_manager.get(flow.flowchart, 'mamu', before_item, flag_event, True)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': "MamuItemGetFlag"}, {0: 'Event14', 1: 'Event98'})
        event_tools.insertEventAfter(flow.flowchart, 'Event10', flag_check)

        self.parent.file_manager.writeFile('Mamu.bfevfl', flow)


    def madBatterChanges(self):
        flow = self.parent.file_manager.readFile('MadBatter.bfevfl')

        # Combine Talk and End entry points into one flow, cutting out the normal choose your upgrade dialogue
        # Then add separate flows for each Mad Batter to give specific items
        event_tools.insertEventAfter(flow.flowchart, 'Event19', 'Event13')

        ## Mad Batter A (bay)
        item1 = self.parent.item_get_manager.get(flow.flowchart, 'mad-batter-bay', None, 'Event23', True)
        event_tools.addEntryPoint(flow.flowchart, 'BatterA')
        subflow_a = event_tools.createSubFlowEvent(flow.flowchart, '', 'talk2', {})
        event_tools.insertEventAfter(flow.flowchart, 'BatterA', subflow_a)
        event_tools.insertEventAfter(flow.flowchart, subflow_a, item1)

        ## Mad Batter B (woods)
        item2 = self.parent.item_get_manager.get(flow.flowchart, 'mad-batter-woods', None, 'Event23', True)
        event_tools.addEntryPoint(flow.flowchart, 'BatterB')
        subflow_b = event_tools.createSubFlowEvent(flow.flowchart, '', 'talk2', {})
        event_tools.insertEventAfter(flow.flowchart, 'BatterB', subflow_b)
        event_tools.insertEventAfter(flow.flowchart, subflow_b, item2)

        ## Mad Batter C (mountain)
        item3 = self.parent.item_get_manager.get(flow.flowchart, 'mad-batter-taltal', None, 'Event23', True)
        event_tools.addEntryPoint(flow.flowchart, 'BatterC')
        subflow_c = event_tools.createSubFlowEvent(flow.flowchart, '', 'talk2', {})
        event_tools.insertEventAfter(flow.flowchart, 'BatterC', subflow_c)
        event_tools.insertEventAfter(flow.flowchart, subflow_c, item3)

        event_tools.setEventSong(flow.flowchart, 'Event18', self.parent.music_randomizer.songs_dict['BGM_MADBATTER'])
        event_tools.setEventSong(flow.flowchart, 'Event150', self.parent.music_randomizer.songs_dict['BGM_MADBATTER'])

        self.parent.file_manager.writeFile('MadBatter.bfevfl', flow)


    def clothesFairyChanges(self):
        flow = self.parent.file_manager.readFile('FairyQueen.bfevfl')

        item2 = self.parent.item_get_manager.get(flow.flowchart, 'D0-fairy-2', 'Event0', 'Event180', True)

        self.parent.item_get_manager.get(flow.flowchart, 'D0-fairy-1', 'Event0', item2, True)

        event_tools.insertEventAfter(flow.flowchart, 'Event128', 'Event58')

        # make the fairy queen send the player to the proper exit if Shuffle Dungeons is on
        if self.parent.settings["Shuffled Dungeons"]:
            ent_keys = list(self.parent.placements['dungeon-entrances'].keys())
            ent_values = list(self.parent.placements['dungeon-entrances'].values())
            d = DUNGEON_ENTRANCES[ent_keys[ent_values.index('color-dungeon')]]
            destin = d[2] + d[3]
            warp_event = event_tools.findEvent(flow.flowchart, 'Event37')
            warp_event.data.params.data['level'] = re.match('(.+)_\\d\\d[A-Z]', destin).group(1)
            warp_event.data.params.data['locator'] = destin

        self.parent.file_manager.writeFile('FairyQueen.bfevfl', flow)


    def invisibleZoraChanges(self):
        flow = self.parent.file_manager.readFile('SecretZora.bfevfl')
        self.parent.item_get_manager.get(flow.flowchart, 'invisible-zora', 'Event23', 'Event27', True)
        event_tools.insertEventAfter(flow.flowchart, 'Event32', 'Event23')
        self.parent.file_manager.writeFile('SecretZora.bfevfl', flow)


    def goriyaChanges(self):
        flow = self.parent.file_manager.readFile('Goriya.bfevfl')

        flag_event = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': "GoriyaItemGetFlag", 'value': True}, 'Event4')

        self.parent.item_get_manager.get(flow.flowchart, 'goriya-trader', 'Event87', flag_event, True)

        flag_check = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': "GoriyaItemGetFlag"}, {0: 'Event7', 1: 'Event15'})
        event_tools.insertEventAfter(flow.flowchart, 'Event24', flag_check)

        self.parent.file_manager.writeFile('Goriya.bfevfl', flow)


    def syrupChanges(self):
        '''Edits the witch to give the randomized item instead of Magic Powder'''

        flow = self.parent.file_manager.readFile('Syrup.bfevfl')

        # check for mushroom first, if the user has it then give the randomized item
        # if not, check if the user has obtained Magic Powder (GetMagicPowder flag)
        # if so, give a full refill for free
        event_tools.insertEventAfter(flow.flowchart, "talk", "Event43")
        check_event = event_tools.createSwitchEvent(flow.flowchart, "EventFlags", "CheckFlag",
            {"symbol": "GetMagicPowder"},
            {0: "Event44", 1: "Event102"})
        event_tools.setSwitchEventCase(flow.flowchart, "Event43", 0, check_event)

        # give the randomized item when trading in the mushroom
        self.parent.item_get_manager.get(flow.flowchart, 'syrup', 'Event93', None, True)

        # event_tools.setEventSong(flow.flowchart, 'Event56', self.music_randomizer.songs_dict['BGM_SHOP_FAST'])
        # event_tools.setEventSong(flow.flowchart, 'Event13', self.music_randomizer.songs_dict['BGM_SHOP_FAST'])

        self.parent.file_manager.writeFile('Syrup.bfevfl', flow)
