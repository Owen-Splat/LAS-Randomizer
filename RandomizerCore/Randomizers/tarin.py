import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Helpers import item_get_manager


class TarinRandomizer:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        flow = self.parent.file_manager.readFile('Tarin.bfevfl')
        self.makeEventChanges(flow.flowchart)
        self.parent.file_manager.writeFile('Tarin.bfevfl', flow)


    def makeEventChanges(self, flowchart):
        """Edits Tarin to detain you based on if you talked to him rather than on having shield"""

        item_key, item_index = self.parent.item_info_manager.getItemInfo("tarin")
        self.parent.item_get_manager.get(flowchart, item_key, item_index, 'Event52', 'Event31')

        # # If reduce-farming is on, and Tarin has boots, also give 20 bombs if Tarin has boots
        # if placements['tarin'] == 'boots' and settings['reduce-farming']:
        #     event_tools.createActionChain(flowchart, 'Event31', [
        #         ('Inventory', 'AddItemByKey', {'itemKey': 'Bomb', 'count': 30, 'index': -1, 'autoEquip': False})
        #     ], 'Event2')

        event0 = event_tools.findEvent(flowchart, 'Event0')
        event78 = event_tools.findEvent(flowchart, 'Event78')
        event0.data.actor = event78.data.actor
        event0.data.actor_query = event78.data.actor_query
        event0.data.params = event78.data.params

        event_defs = []
        sword_num = 0
        shield_num = 0
        bracelet_num = 0

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

        after = 'Event52'
        starting_rupees = self.parent.settings["Rupees"]
        if starting_rupees > 0:
            event_tools.addActorAction(event_tools.findActor(flowchart, 'Link'), 'AddRupee')
            after = event_tools.createActionEvent(flowchart, 'Link', 'AddRupee', {'amount': starting_rupees}, 'Event52')

        if len(event_defs) > 0:
            event_tools.createActionChain(flowchart, 'Event36', event_defs, after)
        else:
            event_tools.insertEventAfter(flowchart, 'Event36', after)
