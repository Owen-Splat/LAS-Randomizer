import RandomizerCore.Tools.event_tools as event_tools


class SeashellMansionRandomizer:
    """Places items on the presents, and adds an item comparison for progressive items and traps"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        if self.parent.thread_active: self.seashellMansionChanges()
        if self.parent.thread_active: self.addItemComparison()


    def seashellMansionChanges(self):
        """Adds the new item key and index to each present"""

        flow = self.parent.file_manager.readFile('ShellMansionMaster.bfevfl')

        item_key, item_index = self.parent.item_info_manager.getItemInfo('5-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event36').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell10'}

        item_key, item_index = self.parent.item_info_manager.getItemInfo('15-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event10').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell20'}

        item_key, item_index = self.parent.item_info_manager.getItemInfo('30-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event11').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell30'}

        item_key, item_index = self.parent.item_info_manager.getItemInfo('50-seashell-reward')
        event_tools.findEvent(flow.flowchart, 'Event13').data.params.data =\
            {'pointIndex': 0, 'itemKey': item_key, 'itemIndex': item_index, 'flag': 'GetSeashell50'}

        self.parent.item_get_manager.get(flow.flowchart, '40-seashell-reward', 'Event91', 'Event79', True)

        # event fixes
        # 40 shells, doesn't use a present box
        event_tools.findEvent(flow.flowchart, 'Event65').data.forks.pop(0)

        event_tools.insertEventAfter(flow.flowchart, 'Event64', 'Event65')

        # Remove the thing to show Link's sword because it will show L1 sword if he has none. 
        sword_check1 = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': "SwordFoundFlag"}, {0: 'Event65', 1: 'Event64'})
        event_tools.insertEventAfter(flow.flowchart, 'Event80', sword_check1)

        # However, leave it the 2nd time if he's going to get one here.
        if self.parent.placements['40-seashell-reward'] != 'sword':
            sword_check2 = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': "SwordFoundFlag"}, {0: 'Event48', 1: 'Event47'})
            event_tools.insertEventAfter(flow.flowchart, 'Event54', sword_check2)

        # Special case, if there is a sword here, then actually give them item before the end of the animation so it looks like the vanilla cutscene :)
        if self.parent.placements['40-seashell-reward'] == 'sword':
            early_give_sword1 = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv1', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
            early_give_sword2 = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv2', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
            sword_check3 = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': "SwordFoundFlag"}, {0: early_give_sword1, 1: early_give_sword2})
            event_tools.insertEventAfter(flow.flowchart, 'Event74', sword_check3)
        else:
            event_tools.insertEventAfter(flow.flowchart, 'Event74', 'Event19')

        self.parent.file_manager.writeFile('ShellMansionMaster.bfevfl', flow)


    def addItemComparison(self):
        """Adds a itemKey comparison and itemGet animation chain to when you open presents"""

        flow = self.parent.file_manager.readFile('ShellMansionPresent.bfevfl')

        sword_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'SwordLv1', -1 , None, 'Event0')
        sword_content_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'SwordLv1'},
            {0: sword_get, 1: 'Event4'})

        shield_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'Shield', -1, None, 'Event0')
        shield_content_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'Shield'},
            {0: shield_get, 1: sword_content_check})

        bracelet_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'PowerBraceletLv1', -1, None, 'Event0')
        bracelet_content_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'PowerBraceletLv1'},
            {0: bracelet_get, 1: shield_content_check})

        red_tunic_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'ClothesRed', -1, None, 'Event0')
        red_tunic_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'ClothesRed'},
            {0: red_tunic_get, 1: bracelet_content_check})

        blue_tunic_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'ClothesBlue', -1, None, 'Event0')
        blue_tunic_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'ClothesBlue'},
            {0: blue_tunic_get, 1: red_tunic_check})

        zap_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'ZapTrap', -1, None, 'Event0')
        zap_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'ZapTrap'},
            {0: zap_get, 1: blue_tunic_check})

        drown_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'DrownTrap', -1, None, 'Event0')
        drown_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'DrownTrap'},
            {0: drown_get, 1: zap_check})

        squish_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'SquishTrap', -1, None, 'Event0')
        squish_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'SquishTrap'},
            {0: squish_get, 1: drown_check})

        deathball_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'DeathballTrap', -1, None, 'Event0')
        deathball_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'DeathballTrap'},
            {0: deathball_get, 1: squish_check})

        quake_get = self.parent.item_get_manager.getWithAnimation(flow.flowchart, 'QuakeTrap', -1, None, 'Event0')
        last_check = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString',
            {'value1': 'itemKey', 'value2': 'QuakeTrap'},
            {0: quake_get, 1: deathball_check})

        if self.parent.settings["Dungeon Maps"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "DungeonMap", last_check, 'Event0')
        if self.parent.settings["Compasses"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "Compass", last_check, 'Event0')
        if self.parent.settings["Stone Beaks"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "StoneBeak", last_check, 'Event0')
        if self.parent.settings["Small Keys"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "SmallKey", last_check, 'Event0')
        if self.parent.settings["Nightmare Keys"] in ("Any Dungeon", "Anywhere"):
            last_check = self.parent.item_get_manager.getKeysanityItem(flow.flowchart, "NightmareKey", last_check, 'Event0')

        event_tools.insertEventAfter(flow.flowchart, 'Event25', last_check)
        self.parent.file_manager.writeFile('ShellMansionPresent.bfevfl', flow)
