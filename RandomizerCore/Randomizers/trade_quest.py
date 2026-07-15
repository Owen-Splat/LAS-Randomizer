import RandomizerCore.Tools.event_tools as event_tools


class TradeQuestRandomizer:
    """Edits various event files for the Trade Quest NPCs to give the randomized items"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('QuadrupletsMother.bfevfl')
            self.mamashaChanges(flow.flowchart)
            self.parent.file_manager.writeFile('QuadrupletsMother.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('RibbonBowWow.bfevfl')
            self.ciaociaoChanges(flow.flowchart)
            self.parent.file_manager.writeFile('RibbonBowWow.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Sale.bfevfl')
            self.saleChanges(flow.flowchart)
            self.parent.file_manager.writeFile('Sale.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Kiki.bfevfl')
            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel('kiki', self.parent.trap_models)
            self.kikiChanges(flow.flowchart, item_key, item_index)
            # # shuffle bridge building music
            # if self.settings['randomize-music']:
            #     event_tools.findEvent(flow.flowchart, 'Event114').data.params.data['label'] = self.songs_dict['BGM_EVENT_MONKEY']
            #     event_tools.addForkEventForks(flow.flowchart, 'Event102', [
            #         event_tools.createActionEvent(flow.flowchart, 'Audio', 'StopBGM',
            #             {'label': self.songs_dict['BGM_EVENT_MONKEY'], 'duration': 0.0})
            #     ])
            self.parent.file_manager.writeFile('Kiki.bfevfl', flow)
            room_data = self.parent.file_manager.readFile('Field_08L.leb')
            kiki_actor = room_data.actors[0]
            stick_actor = room_data.actors[7]
            # move kiki & the stick if open-bridge is on
            if self.parent.settings["Completed Bridge"]:
                kiki_actor.posX += 1.5
                stick_actor.posX += 1.5
                stick_actor.posZ -= 1.5
            # add the model info to the stick actor parameters
            stick_actor.parameters[1] = bytes(model_path, 'utf-8')
            stick_actor.parameters[2] = bytes(model_name, 'utf-8')
            self.parent.file_manager.writeFile('Field_08L.leb', room_data)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Tarin.bfevfl')
            self.tarinChanges(flow.flowchart)
            # # shuffle bees music
            # if self.settings['randomize-music']:
            #     event_tools.findEvent(flow.flowchart, 'Event113').data.params.data['label'] = self.songs_dict['BGM_EVENT_BEE']
            self.parent.file_manager.writeFile('Tarin.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('ChefBear.bfevfl')
            self.chefChanges(flow.flowchart)
            self.parent.file_manager.writeFile('ChefBear.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Papahl.bfevfl')
            self.papahlChanges(flow.flowchart)
            self.parent.file_manager.writeFile('Papahl.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Christine.bfevfl')
            self.christineChanges(flow.flowchart)
            self.parent.file_manager.writeFile('Christine.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('DrWrite.bfevfl')
            self.mrWriteChanges(flow.flowchart)
            self.parent.file_manager.writeFile('DrWrite.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('GrandmaUlrira.bfevfl')
            self.grandmaYahooChanges(flow.flowchart)
            self.parent.file_manager.writeFile('GrandmaUlrira.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('MarthasBayFisherman.bfevfl')
            self.fishermanChanges(flow.flowchart)
            self.parent.file_manager.writeFile('MarthasBayFisherman.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('MermaidMartha.bfevfl')
            self.mermaidChanges(flow.flowchart)
            self.parent.file_manager.writeFile('MermaidMartha.bfevfl', flow)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('MarthaStatue.bfevfl')
            self.statueChanges(flow.flowchart)
            self.parent.file_manager.writeFile('MarthaStatue.bfevfl', flow)


    def mamashaChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'mamasha', 'Event15', None, True)

        event1 = event_tools.findEvent(flowchart, 'Event1')
        event3 = event_tools.findEvent(flowchart, 'Event3')
        event3.data.actor = event1.data.actor
        event3.data.actor_query = event1.data.actor_query
        event3.data.params.data = {'symbol': 'TradeYoshiDollGet'}


    def ciaociaoChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'ciao-ciao', 'Event21', None, True)

        event1 = event_tools.findEvent(flowchart, 'Event1')
        event3 = event_tools.findEvent(flowchart, 'Event3')
        event3.data.actor = event1.data.actor
        event3.data.actor_query = event1.data.actor_query
        event3.data.params.data = {'symbol': 'TradeRibbonGet'}


    def saleChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'sale', 'Event31', None, True)

        event0 = event_tools.findEvent(flowchart, 'Event0')
        event2 = event_tools.findEvent(flowchart, 'Event2')
        event2.data.actor = event0.data.actor
        event2.data.actor_query = event0.data.actor_query
        event2.data.params.data = {'symbol': 'TradeDogFoodGet'}


    def kikiChanges(self, flowchart, item_key, item_index):
        get_event = self.parent.item_get_manager.getWithAnimation(flowchart, item_key, item_index, None, 'Event102')

        bananas_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'TradeBananasGet'}, {0: 'Event118', 1: 'Event32'})

        event_tools.insertEventAfter(flowchart, 'Event91', bananas_check)
        event_tools.insertEventAfter(flowchart, 'Event84', 'Event15') # skip over setting the trade quest slot to be empty
        event_tools.insertEventAfter(flowchart, 'Event29', 'Event88')
        fork = event_tools.findEvent(flowchart, 'Event88')
        fork.data.forks.pop(0)

        if self.parent.settings["Completed Bridge"]:
            event_tools.insertEventAfter(flowchart, 'Event9', 'Event31')
            event_tools.insertEventAfter(flowchart, 'Event10', 'Event31')

            fork = event_tools.findEvent(flowchart, 'Event28')
            fork.data.forks.pop(1)
            fork.data.forks.pop(1)
            fork.data.forks.pop(1)
            fork.data.forks.pop(1)
            fork.data.forks.pop(2)

            fork = event_tools.findEvent(flowchart, 'Event31')
            fork.data.forks.pop(0)

            kiki_gone = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'KikiGone', 'value': True}, get_event)

            event_tools.insertEventAfter(flowchart, 'Event89', kiki_gone)
        else:
            event_tools.insertEventAfter(flowchart, 'Event89', get_event)


    def tarinChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'tarin-ukuku', 'Event130', 'Event29', True)


    def chefChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'chef-bear', 'Event16', None, True) # Event4

        event1 = event_tools.findEvent(flowchart, 'Event1')
        event11 = event_tools.findEvent(flowchart, 'Event11')
        event11.data.actor = event1.data.actor
        event11.data.actor_query = event1.data.actor_query
        event11.data.params.data = {'symbol': 'TradeHoneycombGet'}


    def papahlChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'papahl', 'Event32', 'Event62', True)

        event81 = event_tools.findEvent(flowchart, 'Event81')
        event2 = event_tools.findEvent(flowchart, 'Event2')
        event2.data.actor = event81.data.actor
        event2.data.actor_query = event81.data.actor_query
        event2.data.params.data = {'symbol': 'TradePineappleGet'}


    def christineChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'christine-trade', 'Event15', 'Event22', True)

        event0 = event_tools.findEvent(flowchart, 'Event0')
        event10 = event_tools.findEvent(flowchart, 'Event10')
        event10.data.actor = event0.data.actor
        event10.data.actor_query = event0.data.actor_query
        event10.data.params.data = {'symbol': 'TradeHibiscusGet'}

        event_tools.insertEventAfter(flowchart, 'Event28', 'Event15')

        self.parent.item_get_manager.get(flowchart, 'christine-grateful', 'Event44', 'Event36', True)


    def mrWriteChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'mr-write', 'Event48', 'Event46', True)

        event0 = event_tools.findEvent(flowchart, 'Event0')
        event2 = event_tools.findEvent(flowchart, 'Event2')
        event2.data.actor = event0.data.actor
        event2.data.actor_query = event0.data.actor_query
        event2.data.params.data = {'symbol': 'TradeLetterGet'}

        event_tools.insertEventAfter(flowchart, 'Event7', 'Event47')

        fork = event_tools.findEvent(flowchart, 'Event47')
        fork.data.forks.pop(1)


    def grandmaYahooChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'grandma-yahoo', 'Event54', 'Event33', True)

        broom_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'TradeBroomGet'}, {0: 'Event69', 1: 'Event79'})

        event_tools.insertEventAfter(flowchart, 'Event11', 'Event0')

        event_tools.setSwitchEventCase(flowchart, 'Event0', 0, broom_check)

        event_tools.insertEventAfter(flowchart, 'Event81', 'Event53')

        fork = event_tools.findEvent(flowchart, 'Event53')
        fork.data.forks.pop(1)


    def fishermanChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'bay-fisherman', 'Event28', 'Event42', True)

        event0 = event_tools.findEvent(flowchart, 'Event0')
        event2 = event_tools.findEvent(flowchart, 'Event2')
        event2.data.actor = event0.data.actor
        event2.data.actor_query = event0.data.actor_query
        event2.data.params.data = {'symbol': 'TradeFishingHookGet'}

        event_tools.insertEventAfter(flowchart, 'Event32', 'Event33')

        fork = event_tools.findEvent(flowchart, 'Event27')
        fork.data.forks.pop(1)


    def mermaidChanges(self, flowchart):
        self.parent.item_get_manager.get(flowchart, 'mermaid-martha', 'Event73', 'Event55', True)

        event0 = event_tools.findEvent(flowchart, 'Event0')
        event2 = event_tools.findEvent(flowchart, 'Event2')
        event2.data.actor = event0.data.actor
        event2.data.actor_query = event0.data.actor_query
        event2.data.params.data = {'symbol': 'TradeNecklaceGet'}

        fork = event_tools.findEvent(flowchart, 'Event71')
        fork.data.forks.pop(1)


    def statueChanges(self, flowchart):
        scale_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
        {'symbol': 'TradeMermaidsScaleGet'}, {0: 'Event28', 1: 'Event32'})
        event_tools.setSwitchEventCase(flowchart, 'Event3', 0, scale_check)
