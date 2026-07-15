import RandomizerCore.Tools.event_tools as event_tools


class OwlStatueRandomizer:
    def __init__(self, mod_generator):
        self.parent = mod_generator
        self.makeOwlStatueChanges()


    def makeOwlStatueChanges(self):
        '''Edits the eventflows for the owl statues to give items'''

        if self.parent.settings["Owl Gifts"] in ("Overworld", "All"):
            if self.parent.thread_active:
                flow = self.parent.file_manager.readFile('FieldOwlStatue.bfevfl')
                self.makeFieldChanges(flow.flowchart)
                self.parent.file_manager.writeFile('FieldOwlStatue.bfevfl', flow)

        if self.parent.settings["Owl Gifts"] in ("Dungeons", "All"):
            if self.parent.thread_active:
                flow = self.parent.file_manager.readFile('DungeonOwlStatue.bfevfl')
                self.makeDungeonChanges(flow.flowchart)
                self.parent.file_manager.writeFile('DungeonOwlStatue.bfevfl', flow)

            if self.parent.thread_active:
                room_data = self.parent.file_manager.readFile('Lv01TailCave_04B.leb')
                room_data.actors[0].parameters[0] = bytes('examine_Tail04B', 'utf-8')
                self.parent.file_manager.writeFile('Lv01TailCave_04B.leb', room_data)

            if self.parent.thread_active:
                room_data = self.parent.file_manager.readFile('Lv10ClothesDungeon_06C.leb')
                room_data.actors[9].parameters[0] = bytes('examine_Color06C', 'utf-8')
                self.parent.file_manager.writeFile('Lv10ClothesDungeon_06C.leb', room_data)

            if self.parent.thread_active:
                room_data = self.parent.file_manager.readFile('Lv10ClothesDungeon_07D.leb')
                room_data.actors[4].parameters[0] = bytes('examine_Color07D', 'utf-8')
                self.parent.file_manager.writeFile('Lv10ClothesDungeon_07D.leb', room_data)

            if self.parent.thread_active:
                room_data = self.parent.file_manager.readFile('Lv10ClothesDungeon_05F.leb')
                room_data.actors[4].parameters[0] = bytes('examine_Color05F', 'utf-8')
                self.parent.file_manager.writeFile('Lv10ClothesDungeon_05F.leb', room_data)


    def makeFieldChanges(self, flowchart):
        '''Places items on the field owls. Hint system not implemented'''

        field_owls = {
            'owl-statue-below-D8': 'Event20',
            'owl-statue-pothole': 'Event22',
            'owl-statue-above-cave': 'Event28',
            'owl-statue-moblin-cave': 'Event30',
            'owl-statue-south-bay': 'Event32',
            'owl-statue-desert': 'Event34',
            'owl-statue-maze': 'Event36',
            'owl-statue-taltal-east': 'Event38',
            'owl-statue-rapids': 'Event40'
        }
        for k,v in field_owls.items():
            gift_event = self.parent.item_get_manager.get(flowchart, k, None, None, True)

            flag_set = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
                {'symbol': k, 'value': True}, gift_event)

            flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
                {'symbol': k}, {0: flag_set, 1: None})

            event_tools.insertEventAfter(flowchart, v, flag_check)

        # Now lets prevent Link from backing up. This is what causes the get item animation to sometimes not play
        dist_evs = (
            'Event17',
            'Event41',
            'Event42',
            'Event43',
            'Event44',
            'Event45',
            'Event46',
            'Event47',
            'Event48'
        )
        for ev in dist_evs:
            dist_ev = event_tools.findEvent(flowchart, ev)
            dist_ev.data.params.data['keepPersonalSpace'] = False


    def makeDungeonChanges(self, flowchart):
        '''Places items on the dungeon owls. Hint system not implemented'''

        ### since Tail Cave statues 04B and 05F use the same event, bundle the event into its own entrypoint
        ### then the original entrypoint will be used solely for 05F, and 04B will have its own entrypoint
        ### both will subflow to the shared events and then call the item get animation afterwards
        ### every other statue event can just add the item event after the message fork events
        event_tools.addEntryPoint(flowchart, 'examine_TailShared')
        event_tools.insertEventAfter(flowchart, 'examine_TailShared', 'Event22')

        event_tools.addEntryPoint(flowchart, 'examine_Tail04B')
        subflow_a = event_tools.createSubFlowEvent(flowchart, '', 'examine_TailShared', {})
        event_tools.insertEventAfter(flowchart, 'examine_Tail04B', subflow_a)

        subflow_b = event_tools.createSubFlowEvent(flowchart, '', 'examine_TailShared', {})
        event_tools.insertEventAfter(flowchart, 'examine_Tail04B05F', subflow_b)

        ### all 3 owl statues in Color Dungeon use the same entrypoint, so same thing here
        event_tools.addEntryPoint(flowchart, 'examine_Color06C') # left
        subflow_c = event_tools.createSubFlowEvent(flowchart, '', 'examine_Color', {})
        event_tools.insertEventAfter(flowchart, 'examine_Color06C', subflow_c)

        event_tools.addEntryPoint(flowchart, 'examine_Color07D') # center
        subflow_d = event_tools.createSubFlowEvent(flowchart, '', 'examine_Color', {})
        event_tools.insertEventAfter(flowchart, 'examine_Color07D', subflow_d)

        event_tools.addEntryPoint(flowchart, 'examine_Color05F') # right
        subflow_e = event_tools.createSubFlowEvent(flowchart, '', 'examine_Color', {})
        event_tools.insertEventAfter(flowchart, 'examine_Color05F', subflow_e)

        dungeon_owls = {
            'D1-owl-statue-spinies': subflow_a,
            'D1-owl-statue-3-of-a-kind': subflow_b,
            'D1-owl-statue-long-hallway': 'Event48',
            'D2-owl-statue-first-switch': 'Event59',
            'D2-owl-statue-push-puzzle': 'Event62',
            'D2-owl-statue-past-hinox': 'Event65',
            'D3-owl-statue-basement-north': 'Event27',
            'D3-owl-statue-arrow': 'Event73',
            'D3-owl-statue-northwest': 'Event76',
            'D4-owl-statue': 'Event79',
            'D5-owl-statue-triple-stalfos': 'Event82',
            'D5-owl-statue-before-slime-eel': 'Event85',
            'D6-owl-statue-ledge': 'Event88',
            'D6-owl-statue-southeast': 'Event91',
            'D6-owl-statue-canal': 'Event94',
            'D7-owl-statue-ball': 'Event97',
            'D7-owl-statue-kirbys': 'Event100',
            'D7-owl-statue-hookshot-chest': 'Event103',
            'D8-owl-statue-above-smasher': 'Event39',
            'D8-owl-statue-below-gibdos': 'Event109',
            'D8-owl-statue-eye-statue': 'Event112',
            'D0-owl-statue-nine-switches': subflow_c,
            'D0-owl-statue-first-switches': subflow_d,
            'D0-owl-statue-before-mini-boss': subflow_e
        }
        for k,v in dungeon_owls.items():
            gift_event = self.parent.item_get_manager.get(flowchart, k, None, None, True)

            flag_set = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
                {'symbol': k, 'value': True}, gift_event)

            flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
                {'symbol': k}, {0: flag_set, 1: None})

            event_tools.insertEventAfter(flowchart, v, flag_check)

        # I dont know if the get item animation breaks in dungeons but same thing here as we did with the overworld ones
        fork = event_tools.findEvent(flowchart, 'Event50')
        fork.data.forks.pop(5)
