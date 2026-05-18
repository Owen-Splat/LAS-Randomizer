from RandomizerCore.Tools.event_tools import insertEventAfter, setSwitchEventCase, findEvent


class MadamMeowMeowEventFixes:
    """Change her behaviour to always take back BowWow if you have him, and not do anything based on having the Horn"""

    def __init__(self, mod_generator) -> None:
            flow = mod_generator.file_manager.readFile('MadamMeowMeow.bfevfl')

            # Removes BowWowClear flag being set
            insertEventAfter(flow.flowchart, 'Event69', 'Event18')

            # Rearranging her dialogue conditions
            insertEventAfter(flow.flowchart, 'Event22', 'Event5')
            setSwitchEventCase(flow.flowchart, 'Event5', 0, 'Event0')
            setSwitchEventCase(flow.flowchart, 'Event5', 1, 'Event52')
            setSwitchEventCase(flow.flowchart, 'Event0', 0, 'Event40')
            setSwitchEventCase(flow.flowchart, 'Event0', 1, 'Event21')
            setSwitchEventCase(flow.flowchart, 'Event21', 0, 'Event80')
            findEvent(flow.flowchart, 'Event21').data.params.data['symbol'] = 'BowWowJoin'

            mod_generator.file_manager.writeFile('MadamMeowMeow.bfevfl', flow)
