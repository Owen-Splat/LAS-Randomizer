import RandomizerCore.Tools.event_tools as event_tools


class PrizeCommonEventFixes:
    """Change the figure to look for when the fast-trendy setting is on, and makes Yoshi not replace Lens"""

    def __init__(self, mod_generator) -> None:
        flow = mod_generator.file_manager.readFile('PrizeCommon.bfevfl')
        self.makeEventChanges(flow.flowchart, mod_generator.settings, mod_generator.flag_manager.flags)
        mod_generator.file_manager.writeFile('PrizeCommon.bfevfl', flow)


    def makeEventChanges(self, flowchart, settings: dict, flags: dict):
        # if settings['fast-trendy']:
        #     event_tools.findEvent(flowchart, 'Event5').data.params.data['prizeType'] = 10

        yoshi_lens_get = event_tools.createActionChain(flowchart, None, [
            ('EventFlags', 'SetFlag', {'symbol': 'TradeYoshiDollGet', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': flags["LensFoundFlag"], 'value': True}),
            ('Inventory', 'SetWarashibeItem', {'itemType': 15})
        ], None)
        yoshi_get = event_tools.createActionChain(flowchart, None, [
            ('Inventory', 'SetWarashibeItem', {'itemType': 0}),
            ('EventFlags', 'SetFlag', {'symbol': 'TradeYoshiDollGet', 'value': True})
        ], None)
        lens_flag_check = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag',
            {'symbol': flags["LensFoundFlag"]}, {0: yoshi_get, 1: yoshi_lens_get})
        yoshi_check = event_tools.createSwitchEvent(flowchart, 'Inventory', 'HasItem',
            {'itemType': 30, 'count': 1}, {0: None, 1: lens_flag_check})

        ### CONNECT LENS CHECK TO EVENTS
        event_tools.insertEventAfter(flowchart, 'Event3', yoshi_check)
        event_tools.insertEventAfter(flowchart, 'Event7', yoshi_check)
        event_tools.insertEventAfter(flowchart, 'Event9', yoshi_check)
