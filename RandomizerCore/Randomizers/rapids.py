import RandomizerCore.Tools.event_tools as event_tools


class RapidsRandomizer:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator

        flow = self.parent.file_manager.readFile('RaftShopMan.bfevfl')
        self.makePrizesStack(flow.flowchart)

        # removed rapids BGM because of it being broken in music rando, so remove the StopBGM events for it
        if self.parent.settings["Music"] == "Shuffled":
            event_tools.insertEventAfter(flow.flowchart, 'timeAttackGoal', 'Event27')
            event_tools.insertEventAfter(flow.flowchart, 'normalGoal', 'Event20')

        self.parent.file_manager.writeFile('RaftShopMan.bfevfl', flow)


    def makePrizesStack(self, flowchart):
        """Makes the rapids time attack prizes stack, so getting faster times give the slower prizes as well if you do not have them"""

        # 45 prize event doesn't need anything special :)
        item_key, item_index = self.parent.item_info_manager.getItemInfo("rapids-race-45")
        self.parent.item_get_manager.get(flowchart, item_key, item_index, 'Event42', 'Event88')

        # since these events only get called once by using flags, they each can just check the slower goal, and subflow to it
        item_key, item_index = self.parent.item_info_manager.getItemInfo("rapids-race-35")
        get35 = self.parent.item_get_manager.get(flowchart, item_key, item_index, None, 'Event86')
        subflow45 = event_tools.createSubFlowEvent(flowchart, '', '5minfirst', {}, get35)
        check45 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': '5minGaul'}, {0: subflow45, 1: get35})
        event_tools.insertEventAfter(flowchart, 'Event40', check45)

        # 30 prize just needs to subflow to the 35 prize, as the 35 prize event already checks for the 45
        item_key, item_index = self.parent.item_info_manager.getItemInfo("rapids-race-30")
        get30 = self.parent.item_get_manager.get(flowchart, item_key, item_index, None, 'Event85')
        subflow35 = event_tools.createSubFlowEvent(flowchart, '', '3minfirst', {}, get30)
        check35 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': '3minGaul'}, {0: subflow35, 1: get30})
        event_tools.insertEventAfter(flowchart, 'Event38', check35)
