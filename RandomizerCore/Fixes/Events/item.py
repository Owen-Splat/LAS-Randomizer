import RandomizerCore.Tools.event_tools as event_tools


class ItemEventFixes:
    """Add and fix some entry points for the ItemGetSequence"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        flow = self.parent.file_manager.readFile('Item.bfevfl')
        self.fixEntryPoints(flow.flowchart)
        self.parent.file_manager.writeFile('Item.bfevfl', flow)


    def fixEntryPoints(self, flowchart) -> None:
        event_tools.addEntryPoint(flowchart, 'MagicPowder_MaxUp')
        event_tools.createActionChain(flowchart, 'MagicPowder_MaxUp', [
            ('Dialog', 'Show', {'message': 'SubEvent:ByebyeMadBatter'})
        ])
        event_tools.addEntryPoint(flowchart, 'Bomb_MaxUp')
        event_tools.createActionChain(flowchart, 'Bomb_MaxUp', [
            ('Dialog', 'Show', {'message': 'SubEvent:ByebyeMadBatter'})
        ])
        event_tools.addEntryPoint(flowchart, 'Arrow_MaxUp')
        event_tools.createActionChain(flowchart, 'Arrow_MaxUp', [
            ('Dialog', 'Show', {'message': 'SubEvent:ByebyeMadBatter'})
        ])

        # create message for obtaining the bow, for some weird reason the game doesnt have one when you buy it
        event_tools.addEntryPoint(flowchart, 'Bow')
        event_tools.createActionChain(flowchart, 'Bow', [
            ('Dialog', 'Show', {'message': 'UI:ItemName_Bow'})
        ])

        event_tools.findEntryPoint(flowchart, 'GreenClothes').name = 'ClothesGreen'
        event_tools.findEntryPoint(flowchart, 'RedClothes').name = 'ClothesRed'
        event_tools.findEntryPoint(flowchart, 'BlueClothes').name = 'ClothesBlue'
        event_tools.findEntryPoint(flowchart, 'Necklace').name = 'PinkBra'

        # now we need to add events for Dampe rewards
        event_tools.addEntryPoint(flowchart, 'Dampe1')
        item_key = self.parent.item_defs[self.parent.placements['dampe-page-1']]['item-key']
        if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
            dialog_event = event_tools.createSubFlowEvent(flowchart, '',
                item_key, {})
            event_tools.insertEventAfter(flowchart, 'Dampe1', dialog_event)

        event_tools.addEntryPoint(flowchart, 'DampeHeart')
        item_key = self.parent.item_defs[self.parent.placements['dampe-heart-challenge']]['item-key']
        if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
            dialog_event = event_tools.createSubFlowEvent(flowchart, '',
                item_key, {})
            event_tools.insertEventAfter(flowchart, 'DampeHeart', dialog_event)

        event_tools.addEntryPoint(flowchart, 'Dampe2')
        item_key = self.parent.item_defs[self.parent.placements['dampe-page-2']]['item-key']
        if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
            dialog_event = event_tools.createSubFlowEvent(flowchart, '',
                item_key, {})
            event_tools.insertEventAfter(flowchart, 'Dampe2', dialog_event)

        event_tools.addEntryPoint(flowchart, 'DampeBottle')
        item_key = self.parent.item_defs[self.parent.placements['dampe-bottle-challenge']]['item-key']
        if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
            dialog_event = event_tools.createSubFlowEvent(flowchart, '',
                item_key, {})
            event_tools.insertEventAfter(flowchart, 'DampeBottle', dialog_event)

        event_tools.addEntryPoint(flowchart, 'DampeFinal')
        item_key = self.parent.item_defs[self.parent.placements['dampe-final']]['item-key']
        if not item_key.endswith('Trap') and not item_key.startswith('Clothes'):
            dialog_event = event_tools.createSubFlowEvent(flowchart, '',
                item_key, {})
            event_tools.insertEventAfter(flowchart, 'DampeFinal', dialog_event)
