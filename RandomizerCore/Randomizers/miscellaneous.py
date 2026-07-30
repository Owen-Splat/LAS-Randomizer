import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers.data import MODEL_SIZES, MODEL_ROTATIONS


class MiscRandomizer:
    def __init__(self, mod_generator):
        self.parent = mod_generator
        flow = self.parent.file_manager.readFile('SinkingSword.bfevfl')
        self.changeSunkenSword(flow.flowchart)
        self.changeMushroom(flow.flowchart)
        self.changeOcarina(flow.flowchart)
        self.changeBirdKey(flow.flowchart)
        self.changeLens(flow.flowchart)
        self.parent.file_manager.writeFile('SinkingSword.bfevfl', flow)


    def changeSunkenSword(self, flowchart):
        room_data = self.parent.file_manager.readFile('Field_16C.leb')
        item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel('washed-up')

        if self.parent.settings["Music"] != "Vanilla":
            end_ev = None
            del event_tools.findEvent(flowchart, 'Event0').data.forks[0]
        else:
            end_ev = 'Event8'
        
        self.parent.item_get_manager.get(flowchart, 'washed-up', 'Event5', end_ev)

        fork = event_tools.findEvent(flowchart, 'Event0')
        fork.data.forks.pop(0) # remove the itemget animation event
        event_tools.removeEventAfter(flowchart, 'Event10')
        # event_tools.findEvent(flowchart, 'Event1').data.params.data['itemType'] = -1

        fork = event_tools.findEvent(flowchart, 'Event8')
        fork.data.forks.pop(1) # remove the sword spin attack animation event

        # update the flag set when getting this item
        flag_set = event_tools.findEvent(flowchart, 'Event2')
        flag_set.data.params.data['symbol'] = "BeachMiscItemGetFlag"

        # set y-rotation to be 0, if it's something that needs flipped, it will be handled later
        act = room_data.actors[4]
        act.type = 0xB0 # heart piece
        act.rotY = 0.0
        act.scaleX = 0.55
        act.scaleY = 0.55
        act.scaleZ = 0.55

        # Keep the normal model if it's a sword
        act.parameters[0] = 51 # we can use indexes 50-63 since they are unused
        act.parameters[1] = bytes(model_path, 'utf-8')
        act.parameters[2] = bytes(model_name, 'utf-8')
        act.parameters[3] = bytes('examine', 'utf-8')
        act.parameters[4] = bytes("BeachMiscItemGetFlag", 'utf-8')

        if item_key == 'Seashell':
            act.parameters[5] = bytes('true', 'utf-8')
        else:
            act.parameters[5] = bytes('false', 'utf-8')

        if model_name in MODEL_SIZES:
            size = MODEL_SIZES[model_name]
            act.scaleX = size
            act.scaleY = size
            act.scaleZ = size
        if model_name in MODEL_ROTATIONS:
            act.rotY = MODEL_ROTATIONS[model_name]

        self.parent.file_manager.writeFile('Field_16C.leb', room_data)


    def changeMushroom(self, flowchart):
        room_data = self.parent.file_manager.readFile('Field_06A.leb')
        item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel('woods-loose')

        get_anim = self.parent.item_get_manager.get(flowchart, 'woods-loose')

        event_tools.addEntryPoint(flowchart, 'Woods')
        event_tools.createActionChain(flowchart, 'Woods', [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': "WoodsMiscItemGetFlag", 'value': True})
        ], get_anim)

        act = room_data.actors[3]
        act.type = 0xB0 # heart piece
        act.scaleX = 0.55
        act.scaleY = 0.55
        act.scaleZ = 0.55

        act.parameters[0] = 52 # we can use indexes 50-63 since they are unused
        act.parameters[1] = bytes(model_path, 'utf-8')
        act.parameters[2] = bytes(model_name, 'utf-8')
        act.parameters[3] = bytes('Woods', 'utf-8')
        act.parameters[4] = bytes("WoodsMiscItemGetFlag", 'utf-8')

        if item_key == 'Seashell':
            act.parameters[5] = bytes('true', 'utf-8')
        else:
            act.parameters[5] = bytes('false', 'utf-8')

        if model_name in MODEL_SIZES:
            size = MODEL_SIZES[model_name]
            act.scaleX = size
            act.scaleY = size
            act.scaleZ = size
        if model_name in MODEL_ROTATIONS:
            act.rotY = MODEL_ROTATIONS[model_name]

        self.parent.file_manager.writeFile('Field_06A.leb', room_data)


    def changeOcarina(self, flowchart):
        room_data = self.parent.file_manager.readFile('DreamShrine_01A.leb')
        item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel('dream-shrine-left')

        get_anim = self.parent.item_get_manager.get(flowchart, 'dream-shrine-left')

        event_tools.addEntryPoint(flowchart, 'DreamShrine')
        event_tools.createActionChain(flowchart, 'DreamShrine', [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': "DreamShrineItemGetFlag", 'value': True})
        ], get_anim)

        act = room_data.actors[5]
        act.type = 0x194 # ObjSinkingSword so that the player needs to press A to grab
        act.parameters[0] = bytes(model_path, 'utf-8')
        act.parameters[1] = bytes(model_name, 'utf-8')
        act.parameters[2] = bytes('DreamShrine', 'utf-8')
        act.parameters[3] = bytes("DreamShrineItemGetFlag", 'utf-8') # category 1

        if item_key == 'Seashell':
            act.parameters[4] = bytes('true', 'utf-8')
        else:
            act.parameters[4] = bytes('false', 'utf-8')

        if model_name in MODEL_SIZES:
            size = MODEL_SIZES[model_name]
            act.scaleX = size
            act.scaleY = size
            act.scaleZ = size
        if model_name in MODEL_ROTATIONS:
            act.rotY = MODEL_ROTATIONS[model_name]

        self.parent.file_manager.writeFile('DreamShrine_01A.leb', room_data)


    def changeBirdKey(self, flowchart):
        room_data = self.parent.file_manager.readFile('EagleKeyCave_01A.leb')
        item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel('taltal-rooster-cave')

        get_anim = self.parent.item_get_manager.get(flowchart, 'taltal-rooster-cave')

        event_tools.addEntryPoint(flowchart, 'TalTal')
        event_tools.createActionChain(flowchart, 'TalTal', [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': "RoosterCaveItemGetFlag", 'value': True})
        ], get_anim)

        act = room_data.actors[0]
        act.type = 0xB0 # heart piece
        act.scaleX = 0.55
        act.scaleY = 0.55
        act.scaleZ = 0.55

        act.parameters[0] = 53 # we can use indexes 50-63 since they are unused
        act.parameters[1] = bytes(model_path, 'utf-8')
        act.parameters[2] = bytes(model_name, 'utf-8')
        act.parameters[3] = bytes('TalTal', 'utf-8')
        act.parameters[4] = bytes("RoosterCaveItemGetFlag", 'utf-8')

        if item_key == 'Seashell':
            act.parameters[5] = bytes('true', 'utf-8')
        else:
            act.parameters[5] = bytes('false', 'utf-8')

        if model_name in MODEL_SIZES:
            size = MODEL_SIZES[model_name]
            act.scaleX = size
            act.scaleY = size
            act.scaleZ = size
        if model_name in MODEL_ROTATIONS:
            act.rotY = MODEL_ROTATIONS[model_name]

        self.parent.file_manager.writeFile('EagleKeyCave_01A.leb', room_data)


    def changeLens(self, flowchart):
        room_data = self.parent.file_manager.readFile('MermaidStatue_01A.leb')
        item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel('mermaid-cave')

        get_anim = self.parent.item_get_manager.get(flowchart, 'mermaid-cave')

        event_tools.addEntryPoint(flowchart, 'MermaidCave')
        event_tools.createActionChain(flowchart, 'MermaidCave', [
            ('SinkingSword', 'Destroy', {}),
            ('EventFlags', 'SetFlag', {'symbol': "MermaidCaveItemGetFlag", 'value': True})
        ], get_anim)

        act = room_data.actors[7]
        act.type = 0xB0 # heart piece
        act.rotY = 0 # rotate to be facing the screen

        if model_name not in ("HeartPiece", "HeartContainer"):
            act.scaleX = 0.55
            act.scaleY = 0.55
            act.scaleZ = 0.55

        act.parameters[0] = 54 # we can use indexes 50-63 since they are unused
        act.parameters[1] = bytes(model_path, 'utf-8')
        act.parameters[2] = bytes(model_name, 'utf-8')
        act.parameters[3] = bytes('MermaidCave', 'utf-8')
        act.parameters[4] = bytes("MermaidCaveItemGetFlag", 'utf-8')

        if item_key == 'Seashell':
            act.parameters[5] = bytes('true', 'utf-8')
        else:
            act.parameters[5] = bytes('false', 'utf-8')

        if model_name in MODEL_SIZES:
            size = MODEL_SIZES[model_name]
            act.scaleX = size
            act.scaleY = size
            act.scaleZ = size
        if model_name in MODEL_ROTATIONS:
            act.rotY = MODEL_ROTATIONS[model_name]

        self.parent.file_manager.writeFile('MermaidStatue_01A.leb', room_data)
