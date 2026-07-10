import RandomizerCore.Tools.event_tools as event_tools


class SkeletalGuardEventFixes:
    """Make the blue guard sell 20 bombs in addition to the 20 powder"""

    def __init__(self, mod_generator) -> None:
            flow = mod_generator.file_manager.readFile('SkeletalGuardBlue.bfevfl')

            # edit Magic Powder amount from 20 to 40 so that it'll max even with the capacity upgrade
            event_tools.findEvent(flow.flowchart, 'Event19').data.params.data['count'] = 40

            # check GetMagicPowder flag before buying
            # these guards will no longer be a source for getting your main powder
            if mod_generator.settings["Shuffled Powder"]:
                check_powder = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
                    {'symbol': 'GetMagicPowder'}, {0: 'Event54', 1: 'Event46'})
                event_tools.setSwitchEventCase(flow.flowchart, 'Event7', 1, check_powder)

            mod_generator.file_manager.writeFile('SkeletalGuardBlue.bfevfl', flow)
