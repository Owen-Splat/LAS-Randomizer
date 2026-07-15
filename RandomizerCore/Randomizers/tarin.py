import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Helpers import item_get_manager


class TarinRandomizer:
    """Handles randomizing the item Tarin gives, as well as to give all the starting items

    Will later be moved to player_start.py when we randomize starting location"""

    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator
        flow = self.parent.file_manager.readFile('Tarin.bfevfl')
        self.makeEventChanges(flow.flowchart)
        self.parent.file_manager.writeFile('Tarin.bfevfl', flow)


    def makeEventChanges(self, flowchart):
        """Edits Tarin to detain you based on if you talked to him rather than on having shield"""

        self.parent.item_get_manager.get(flowchart, "tarin", 'Event52', 'Event31', True)

        event0 = event_tools.findEvent(flowchart, 'Event0')
        event78 = event_tools.findEvent(flowchart, 'Event78')
        event0.data.actor = event78.data.actor
        event0.data.actor_query = event78.data.actor_query
        event0.data.params = event78.data.params
