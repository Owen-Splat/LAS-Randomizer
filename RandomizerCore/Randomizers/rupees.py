import RandomizerCore.Tools.event_tools as event_tools


class BlueRupeeRandomizer:
    def __init__(self, mod_generator):
        self.parent = mod_generator
        if self.parent.settings["Blue Rupees"]:
            self.makeLv10RupeeChanges()


    def makeLv10RupeeChanges(self):
        """Edits the room data for the 28 free standing rupees in Color Dungeon so they are randomized"""

        flow = self.parent.file_manager.readFile('SinkingSword.bfevfl')
        room_data = self.parent.file_manager.readFile('Lv10ClothesDungeon_08D.leb')

        for i in range(28):
            if not self.parent.thread_active:
                break

            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(f'D0-rupee-{i + 1}', self.parent.dungeon_trap_models)
            room_data.setRupeeParams(model_path, model_name, f'Lv10Rupee_{i + 1}', item_key, i)
            self.makeEventChanges(flow.flowchart, i, f'D0-rupee-{i + 1}')

        self.parent.file_manager.writeFile('Lv10ClothesDungeon_08D.leb', room_data)
        self.parent.file_manager.writeFile('SinkingSword.bfevfl', flow)


    def makeEventChanges(self, flowchart, rup_index, check):
        """Adds an entry point to the flowchart for each rupee, and inserts the ItemGetAnimation event into it"""

        event_tools.addEntryPoint(flowchart, f'Lv10Rupee_{rup_index + 1}')

        get_anim = self.parent.item_get_manager.get(flowchart, check)

        event_tools.createActionChain(flowchart, f'Lv10Rupee_{rup_index + 1}', [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': 'Lv10RupeeGet' if rup_index == 0 else f'Lv10RupeeGet_{rup_index + 1}', 'value': True})
        ], get_anim)
