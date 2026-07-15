import RandomizerCore.Tools.event_tools as event_tools


class FishingRandomizer:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        flow = self.parent.file_manager.readFile('Fisherman.bfevfl')
        self.makeEventChanges(flow.flowchart)
        self.parent.file_manager.writeFile('Fisherman.bfevfl', flow)


    def makeEventChanges(self, flowchart):
        change_defs = [
            ('fishing-orange', 'Event113', 'Event212'),
            ('fishing-cheep-cheep', 'Event3', 'Event10'),
            ('fishing-ol-baron', 'Event133', 'Event140'),
            ('fishing-50', 'Event182', 'Event240'),
            ('fishing-100', 'Event191', 'Event247'),
            ('fishing-150', 'Event193', 'Event255'),
            ('fishing-loose', 'Event264', 'Event265')
        ]

        for defs in change_defs:
            self.parent.item_get_manager.get(flowchart, defs[0], defs[1], defs[2], True)

        bottle_get = event_tools.createActionEvent(flowchart, 'EventFlags', 'SetFlag',
            {'symbol': 'FishingBottleGet', 'value': True}, 'Event264')

        event_tools.insertEventAfter(flowchart, 'Event20', 'Event3')
        event_tools.insertEventAfter(flowchart, 'Event18', 'Event133')
        event_tools.insertEventAfter(flowchart, 'Event24', 'Event191')
        event_tools.insertEventAfter(flowchart, 'FishingGetBottle', bottle_get)
