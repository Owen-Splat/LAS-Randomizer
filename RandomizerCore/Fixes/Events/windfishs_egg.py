from RandomizerCore.Tools.event_tools import insertEventAfter


class WindFishsEggEventFixes:
    """Removes the Owl cutscene after opening the egg"""

    def __init__(self, mod_generator) -> None:
        flow = mod_generator.file_manager.readFile('WindFishsEgg.bfevfl')
        insertEventAfter(flow.flowchart, 'Event142', None)
        mod_generator.file_manager.writeFile('WindFishsEgg.bfevfl', flow)
