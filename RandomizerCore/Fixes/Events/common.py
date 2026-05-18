import RandomizerCore.Tools.event_tools as event_tools


class CommonEventFixes:
    """Make Save&Quit after getting a GameOver send you back to Marin's house

    Also shuffles the rapids race music"""

    def __init__(self, mod_generator) -> None:
        flow = mod_generator.file_manager.readFile('Common.bfevfl')

        event_tools.setSwitchEventCase(flow.flowchart, 'Event64', 1,
            event_tools.createActionEvent(flow.flowchart, 'GameControl', 'RequestLevelJump',
                {'level': 'Field', 'locator': 'Field_11C', 'offsetX': 0.0, 'offsetZ': 0.0},
                'Event67'))

        # shuffle Rapids race music
        if mod_generator.settings["Music"] == "Shuffled":
            # remove the music for now since it gets cut off due to something with setting the new BGM in the lvb file
            event_tools.insertEventAfter(flow.flowchart, 'Event167', None)
            #
            # event_tools.findEvent(flow.flowchart, 'Event78').data.params.data['label'] = mod_generator.music_randomizer.songs_dict['BGM_RAFTING_TIMEATTACK']

        mod_generator.file_manager.writeFile('Common.bfevfl', flow)
