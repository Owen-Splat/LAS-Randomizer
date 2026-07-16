import RandomizerCore.Tools.event_tools as event_tools


class ShopRandomizer:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        self.makeDatasheetChanges()
        self.makeBuyingEventChanges()
        self.makeStealingEventChanges()
        self.makeTextChanges()


    def makeDatasheetChanges(self):
        """Edit the ShopItem datasheet to for the new items. Incomplete, does not yet randomize the chamber stones"""

        sheet = self.parent.file_manager.readFile('ShopItem.gsheet')

        for slot in sheet['values']:
            if slot['mIndex'] == 2:
                item_key, item_index, model_path, model_name =\
                    self.parent.item_info_manager.getItemInfoWithModel('shop-slot3-1st', self.parent.dungeon_trap_models)
                slot['mGoods'][0]['mItem'] = 'ShopShovel'
                slot['mGoods'][0]['mModelPath'] = f"actor/{model_path}"
                slot['mGoods'][0]['mModelName'] = model_name
                slot['mGoods'][0]['mIndex'] = -1

                item_key, item_index, model_path, model_name =\
                    self.parent.item_info_manager.getItemInfoWithModel('shop-slot3-2nd', self.parent.dungeon_trap_models)
                slot['mGoods'][1]['mItem'] = 'ShopBow'
                slot['mGoods'][1]['mModelPath'] = f"actor/{model_path}"
                slot['mGoods'][1]['mModelName'] = model_name
                slot['mGoods'][1]['mIndex'] = -1

            if slot['mIndex'] == 5:
                item_key, item_index, model_path, model_name =\
                    self.parent.item_info_manager.getItemInfoWithModel('shop-slot6', self.parent.dungeon_trap_models)
                slot['mGoods'][0]['mItem'] = 'ShopHeart'
                slot['mGoods'][0]['mModelPath'] = f"actor/{model_path}"
                slot['mGoods'][0]['mModelName'] = model_name
                slot['mGoods'][0]['mIndex'] = -1

        self.parent.file_manager.writeFile('ShopItem.gsheet', sheet)


    def makeBuyingEventChanges(self):
        """Edit the ToolShopKeeper buying events to give the new items"""

        flow = self.parent.file_manager.readFile('ToolShopkeeper.bfevfl')

        # shovel
        item_key, item_index = self.parent.item_info_manager.getItemInfo('shop-slot3-1st')
        event_tools.setSwitchEventCase(flow.flowchart, 'Event50', 1, 'Event52')
        event_tools.insertEventAfter(flow.flowchart, 'Event52', 'Event61')
        self.parent.item_get_manager.getWithAnimation(flow.flowchart, item_key, item_index, 'Event53', 'Event43')
        event_tools.findEvent(flow.flowchart, 'Event43').data.params.data['symbol'] = 'ShopShovelGet'

        # bow
        item_key, item_index = self.parent.item_info_manager.getItemInfo('shop-slot3-2nd')
        event_tools.setSwitchEventCase(flow.flowchart, 'Event12', 1, 'Event14')
        event_tools.insertEventAfter(flow.flowchart, 'Event14', 'Event65')
        self.parent.item_get_manager.getWithAnimation(flow.flowchart, item_key, item_index, 'Event17', 'Event151')
        event_tools.findEvent(flow.flowchart, 'Event151').data.params.data['symbol'] = 'ShopBowGet'

        # heart piece
        item_key, item_index = self.parent.item_info_manager.getItemInfo('shop-slot6')
        set_flag = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'ShopHeartGet', 'value': True})
        self.parent.item_get_manager.getWithAnimation(flow.flowchart, item_key, item_index, 'Event122', set_flag)

        self.parent.file_manager.writeFile('ToolShopkeeper.bfevfl', flow)


    def makeStealingEventChanges(self, flowchart, placements, item_defs):
        """Edits the ExitOutShop event to give the stolen items with an animation

        Also unsets the flag that would cause the Shopkeeper to kill you"""

        flow = self.parent.file_manager.readFile('PlayerStart.bfevfl')

        # Remove the flag that says you stole so that the shopkeeper won't kill you
        event_tools.createActionChain(flow.flowchart, 'Event774', [
            ('EventFlags', 'SetFlag', {'symbol': 'StealSuccess', 'value': False})
        ])

        # Now check for stolen item flags, if true, play the get animation and unset the flag so it won't play again
        # then set the shop condition flag so it won't appear anymore
        remove_heart = event_tools.createActionChain(flow.flowchart, None, [
            ('EventFlags', 'SetFlag', {'symbol': 'ShopHeartGet', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'ShopHeartSteal', 'value': False}),
        ], None)
        give_heart = self.parent.item_get_manager.get(flow.flowchart, 'shop-slot6', None, remove_heart, True)
        check_heart = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'ShopHeartSteal'}, {0: None, 1: give_heart})

        remove_bow = event_tools.createActionChain(flow.flowchart, None, [
            ('EventFlags', 'SetFlag', {'symbol': 'ShopBowGet', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'BowGet', 'value': False}),
        ], check_heart)
        give_bow = self.parent.item_get_manager.get(flow.flowchart, 'shop-slot3-2nd', None, remove_bow, True)
        check_bow = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'BowGet'}, {0: check_heart, 1: give_bow})

        remove_shovel = event_tools.createActionChain(flow.flowchart, None, [
            ('EventFlags', 'SetFlag', {'symbol': 'ShopShovelGet', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'ScoopGet', 'value': False}),
        ], check_bow)
        give_shovel = self.parent.item_get_manager.get(flow.flowchart, 'shop-slot3-1st', None, remove_shovel, True)
        check_shovel = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'ScoopGet'}, {0: check_bow, 1: give_shovel})

        # Insert our events before the nag message over stealing, no event after so it is fully removed
        event_tools.insertEventAfter(flow.flowchart, 'Event771', check_shovel)

        self.parent.file_manager.writeFile('PlayerStart.bfevfl', flow)


    def makeTextChanges(self) -> None:
        return
