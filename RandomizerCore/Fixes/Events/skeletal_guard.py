import RandomizerCore.Tools.event_tools as event_tools


class SkeletalGuardEventFixes:
    """Make the blue guard sell 20 bombs in addition to the 20 powder"""

    def __init__(self, mod_generator) -> None:
            flow = mod_generator.file_manager.readFile('SkeletalGuardBlue.bfevfl')

            # edit Magic Powder amount from 20 to 40 so that it'll max even with the capacity upgrade
            event_tools.findEvent(flow.flowchart, 'Event19').data.params.data['count'] = 40

            # give 60 Bombs so that it'll max even with the capacity upgrade
            add_bombs = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItem',
                {'itemType': 4, 'count': 60, 'autoEquip': False})

            # check GetMagicPowder flag before buying
            # these guards will no longer be a source for getting your main powder, and cannot sell bombs until the player can buy powder
            if mod_generator.settings["Shuffled Powder"]:
                check_powder = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
                    {'symbol': 'GetMagicPowder'}, {0: 'Event54', 1: 'Event46'})
                event_tools.setSwitchEventCase(flow.flowchart, 'Event7', 1, check_powder)

            # check BombsFound flag when buying powder so we can give some additional resources if available
            # these guards are not a source for getting your main bombs
            if mod_generator.settings["Shuffled Bombs"]:
                check_bombs = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag',
                    {'symbol': mod_generator.flag_manager.flags["BombsFoundFlag"]}, {0: None, 1: add_bombs})
                event_tools.insertEventAfter(flow.flowchart, 'Event19', check_bombs)
            else:
                event_tools.insertEventAfter(flow.flowchart, 'Event19', add_bombs)

            mod_generator.file_manager.writeFile('SkeletalGuardBlue.bfevfl', flow)
