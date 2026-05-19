import RandomizerCore.Tools.event_tools as event_tools


class DampeRandomizer:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator

        if self.parent.thread_active:
            sheet = self.parent.file_manager.readFile('MapPieceClearReward.gsheet')
            self.makeDatasheetChanges(sheet, 3, 'Dampe1')
            self.makeDatasheetChanges(sheet, 7, 'Dampe2')
            self.makeDatasheetChanges(sheet, 12, 'DampeFinal')
            self.parent.file_manager.writeFile('MapPieceClearReward.gsheet', sheet)

        if self.parent.thread_active:
            sheet = self.parent.file_manager.readFile('MapPieceTheme.gsheet')
            self.makeDatasheetChanges(sheet, 3, 'DampeHeart')
            self.makeDatasheetChanges(sheet, 9, 'DampeBottle')
            self.parent.file_manager.writeFile('MapPieceTheme.gsheet', sheet)

        if self.parent.thread_active:
            flow = self.parent.file_manager.readFile('Danpei.bfevfl')
            self.makeEventChanges(flow.flowchart)
            self.parent.file_manager.writeFile('Danpei.bfevfl', flow)


    def makeDatasheetChanges(self, sheet, reward_num, item_key):
        """Edits the Dampe rewards datasheets to give fake items

        The fake items set flags which are then used to do the real work after"""

        sheet['values'][reward_num]['mRewardItem'] = item_key
        sheet['values'][reward_num]['mRewardItemIndex'] = 0
        sheet['values'][reward_num]['mRewardItemEventEntry'] = item_key


    def makeEventChanges(self, flowchart):
        """Make Dampe perform inventory and flag checks before and after the reward event"""

        remove_final = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'DampeFinal', 'value': False}, 'Event42')
        give_final = self.parent.item_get_manager.getForDampe(flowchart,
            self.parent.item_defs[self.parent.placements['dampe-final']]['item-key'],
            self.parent.placements['indexes']['dampe-final'] if 'dampe-final' in self.parent.placements['indexes'] else -1,
            remove_final)
        check_final = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'DampeFinal'}, {0: 'Event42', 1: give_final})

        remove_bottle = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'DampeBottle', 'value': False}, check_final)
        give_bottle = self.parent.item_get_manager.getForDampe(flowchart,
            self.parent.item_defs[self.parent.placements['dampe-bottle-challenge']]['item-key'],
            self.parent.placements['indexes']['dampe-bottle-challenge'] if 'dampe-bottle-challenge' in self.parent.placements['indexes'] else -1,
            remove_bottle)
        check_bottle = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'DampeBottle'}, {0: check_final, 1: give_bottle})

        remove_page2 = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'Dampe2', 'value': False}, check_bottle)
        give_page2 = self.parent.item_get_manager.getForDampe(flowchart,
            self.parent.item_defs[self.parent.placements['dampe-page-2']]['item-key'],
            self.parent.placements['indexes']['dampe-page-2'] if 'dampe-page-2' in self.parent.placements['indexes'] else -1,
            remove_page2)
        check_page2 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'Dampe2'}, {0: check_bottle, 1: give_page2})

        remove_heart = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'DampeHeart', 'value': False}, check_page2)
        give_heart = self.parent.item_get_manager.getForDampe(flowchart,
            self.parent.item_defs[self.parent.placements['dampe-heart-challenge']]['item-key'],
            self.parent.placements['indexes']['dampe-heart-challenge'] if 'dampe-heart-challenge' in self.parent.placements['indexes'] else -1,
            remove_heart)
        check_heart = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'DampeHeart'}, {0: check_page2, 1: give_heart})

        remove_page1 = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'Dampe1', 'value': False}, check_heart)
        give_page1 = self.parent.item_get_manager.getForDampe(flowchart,
            self.parent.item_defs[self.parent.placements['dampe-page-1']]['item-key'],
            self.parent.placements['indexes']['dampe-page-1'] if 'dampe-page-1' in self.parent.placements['indexes'] else -1,
            remove_page1)
        check_page1 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': 'Dampe1'}, {0: check_heart, 1: give_page1})

        event_tools.insertEventAfter(flowchart, 'Event39', check_page1)
