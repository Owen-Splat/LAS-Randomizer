import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Tools.text_tools import TextFile
from pathlib import Path


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

        # bow
        item_key, item_index = self.parent.item_info_manager.getItemInfo('shop-slot3-2nd')
        event_tools.setSwitchEventCase(flow.flowchart, 'Event12', 1, 'Event14')
        event_tools.insertEventAfter(flow.flowchart, 'Event14', 'Event65')
        self.parent.item_get_manager.getWithAnimation(flow.flowchart, item_key, item_index, 'Event17', 'Event151')

        # heart piece
        item_key, item_index = self.parent.item_info_manager.getItemInfo('shop-slot6')
        set_flag = event_tools.createActionEvent(flow.flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'ShopHeartGet', 'value': True})
        self.parent.item_get_manager.getWithAnimation(flow.flowchart, item_key, item_index, 'Event122', set_flag)

        self.parent.file_manager.writeFile('ToolShopkeeper.bfevfl', flow)


    def makeStealingEventChanges(self):
        """Edits the ExitOutShop event to give the stolen items with an animation

        Also unsets the flag that would cause the Shopkeeper to kill you"""

        flow = self.parent.file_manager.readFile('PlayerStart.bfevfl')

        # Remove the flag that says you stole so that the shopkeeper won't kill you
        fast_stealing = event_tools.createActionChain(flow.flowchart, 'Event774', [
            ('EventFlags', 'SetFlag', {'symbol': 'StealSuccess', 'value': False})
        ])

        # Now check for stolen item flags, if true, play the get animation and unset the flag so it won't play again
        # then set the shop condition flag so it won't appear anymore
        remove_heart = event_tools.createActionChain(flow.flowchart, None, [
            ('EventFlags', 'SetFlag', {'symbol': 'ShopHeartGet', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'ShopHeartSteal', 'value': False}),
        ], fast_stealing)
        give_heart = self.parent.item_get_manager.get(flow.flowchart, 'shop-slot6', None, remove_heart, True)
        check_heart = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'ShopHeartSteal'}, {0: fast_stealing, 1: give_heart})

        remove_bow = event_tools.createActionChain(flow.flowchart, None, [
            ('EventFlags', 'SetFlag', {'symbol': 'BowGet', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'ShopBowSteal', 'value': False}),
        ], check_heart)
        give_bow = self.parent.item_get_manager.get(flow.flowchart, 'shop-slot3-2nd', None, remove_bow, True)
        check_bow = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'ShopBowSteal'}, {0: check_heart, 1: give_bow})

        remove_shovel = event_tools.createActionChain(flow.flowchart, None, [
            ('EventFlags', 'SetFlag', {'symbol': 'ScoopGet', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'ShopShovelSteal', 'value': False}),
        ], check_bow)
        give_shovel = self.parent.item_get_manager.get(flow.flowchart, 'shop-slot3-1st', None, remove_shovel, True)
        check_shovel = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'ShopShovelSteal'}, {0: check_bow, 1: give_shovel})

        # Insert our events before the nag message over stealing, no event after so it is fully removed
        event_tools.insertEventAfter(flow.flowchart, 'Event771', check_shovel)

        self.parent.file_manager.writeFile('PlayerStart.bfevfl', flow)


    def makeTextChanges(self) -> None:
        """Edits the text for the shop items to display the item name and cost

        TBD on what to display for traps. Custom text would be cool but not cross-language.
        Perhaps simply just a mismatch of model and item name would work"""

        for location, messages in TEXT_TO_CHANGE.items():
            # first we need to get the item names in every language
            item = self.parent.placements[location]
            message: str = self.parent.item_defs[item]["message"]
            file_name, entry_name = message.split(':')
            text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles(f"{file_name}.msbt")
            item_names = []
            for file in text_files:
                relative_path, msbt = file
                entry = msbt.getEntry(entry_name)
                item_names.append(entry.message.text)
            text_files.clear()
                
            # now we replace the text in every language with the new item name
            entry1, entry2 = messages
            text_files: list[tuple[Path, TextFile]] = self.parent.file_manager.getAllTextFiles("System.msbt")
            for i, file in enumerate(text_files):
                relative_path, msbt = file
                # entry1
                entry = msbt.getEntry(entry1)
                text = entry.message.text.split("\n")
                text[0] = item_names[i]
                entry.message.text = "\n".join(text)
                # entry2
                entry = msbt.getEntry(entry2)
                rupee_text = entry.message.text.split(msbt.COMMANDS["COLOR_PINK"])[1].split(msbt.COMMANDS["COLOR_WHITE"])[0]
                choice_top = entry.message.text.split(msbt.COMMANDS["CHOICE_TOP"])[1].split(msbt.COMMANDS["CHOICE_BOTTOM"])[0]
                choice_bottom = entry.message.text.split(msbt.COMMANDS["CHOICE_BOTTOM"])[1]
                new_text = f"{item_names[i]}\n[COLOR_PINK]{rupee_text}[COLOR_WHITE][CHOICE_TOP]{choice_top}[CHOICE_BOTTOM]{choice_bottom}"
                msbt.addEntry(entry2, new_text)
                self.parent.file_manager.writeTextFile(relative_path, "System.msbt", msbt)

            # new_text = f"{display_name}\n[COLOR_PINK]{cost} {rupees_language_name}[COLOR_WHITE][WAIT]"


TEXT_TO_CHANGE = { # need to edit 2 messages, display and talking to buy, both in System.msbt
    "shop-slot3-1st":       ("PriceTagScoop",        "BuyScoop"),
    "shop-slot3-2nd":       ("PriceTagBow",          "BuyBow"),
    "shop-slot6":           ("PriceTagHeartPeace",   "BuyHeartPeace")
}