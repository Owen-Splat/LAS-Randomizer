import RandomizerCore.Tools.event_tools as event_tools
import copy


class SeashellRandomizer:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator

        self.flow = self.parent.file_manager.readFile('SmallKey.bfevfl')

        # we are using unused local flags to spawn stuff the items
        # we are close to what I believe is the limit to global flags
        # might be possible to tell the game to allocate more space, I have not tried yet
        self.local_flag_index = 50

        self.addBushDrops()
        self.addRockDrops()
        self.addTreeDrops()
        self.addHoleDrops()

        self.parent.file_manager.writeFile('SmallKey.bfevfl', self.flow)


    def addBushDrops(self) -> None:
        for room in GRASS_ROOMS:
            room_data = self.parent.file_manager.readFile(f"{GRASS_ROOMS[room]}.leb")

            grass = [a for a in room_data.actors if isinstance(a.parameters[1], bytes) and str(a.parameters[1], "utf-8").startswith("Seashell")][0]
            grass.parameters[1] = bytes("None", "utf-8")
            grass.switches[0] = (0, self.local_flag_index)
            key = copy.deepcopy(grass)
            key.key += 1
            key.name = bytes(f"ItemSmallKey-{hex(key.key)[2:].upper()}", "utf-8")
            key.type = 0xa9 # small key
            key.rotY = 0
            key.switches[1] = (1, self.parent.flag_manager.flags[GRASS_FLAGS[room]])
            room_data.actors.append(key)
            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.trap_models)
            room_data.setSmallKeyParams(model_path, model_name, room, item_key)
            self.writeKeyEvent(self.flow.flowchart, item_key, item_index, room)

            self.parent.file_manager.writeFile(f"{GRASS_ROOMS[room]}.leb", room_data)
            self.local_flag_index += 1


    def addRockDrops(self) -> None:
        for room in ROCK_ROOMS:
            room_data = self.parent.file_manager.readFile(f"{ROCK_ROOMS[room]}.leb")

            rock = [a for a in room_data.actors if isinstance(a.parameters[0], bytes) and str(a.parameters[0], "utf-8").startswith("Seashell")][0]
            rock.parameters[0] = bytes("None", "utf-8")
            rock.switches[0] = (0, self.local_flag_index)
            key = copy.deepcopy(rock)
            key.key += 1
            key.name = bytes(f"ItemSmallKey-{hex(key.key)[2:].upper()}", "utf-8")
            key.type = 0xa9 # small key
            key.rotY = 0
            key.switches[1] = (1, self.parent.flag_manager.flags[ROCK_FLAGS[room]])
            room_data.actors.append(key)
            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.trap_models)
            room_data.setSmallKeyParams(model_path, model_name, room, item_key)
            self.writeKeyEvent(self.flow.flowchart, item_key, item_index, room)

            self.parent.file_manager.writeFile(f"{ROCK_ROOMS[room]}.leb", room_data)
            self.local_flag_index += 1


    def addTreeDrops(self) -> None:
        """Adds small keys where the item in the tree would land

        We use exlaunch to force the tree to set its switch0 when bonked"""

        for room in TREE_ROOMS:
            room_data = self.parent.file_manager.readFile(f"{TREE_ROOMS[room]}.leb")

            tree = [a for a in room_data.actors if isinstance(a.parameters[0], bytes) and str(a.parameters[0], "utf-8").startswith("Seashell")][0]
            tree.parameters[0] = bytes("Tree", "utf-8")
            tree.switches[0] = (0, self.local_flag_index)
            key = copy.deepcopy(tree)
            key.key += 1
            key.name = bytes(f"ItemSmallKey-{hex(key.key)[2:].upper()}", "utf-8")
            key.type = 0xa9 # small key
            key.posX = TREE_DROP_POSITIONS[room][0]
            key.posY = TREE_DROP_POSITIONS[room][1]
            key.posZ = TREE_DROP_POSITIONS[room][2]
            key.rotY = 0
            key.switches[1] = (1, self.parent.flag_manager.flags[TREE_FLAGS[room]])
            room_data.actors.append(key)
            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.trap_models)
            room_data.setSmallKeyParams(model_path, model_name, room, item_key)
            self.writeKeyEvent(self.flow.flowchart, item_key, item_index, room)

            self.parent.file_manager.writeFile(f"{TREE_ROOMS[room]}.leb", room_data)
            self.local_flag_index += 1


    def addHoleDrops(self) -> None:
        for room in HOLE_ROOMS:
            room_data = self.parent.file_manager.readFile(f"{HOLE_ROOMS[room]}.leb")

            hole = [a for a in room_data.actors if a.type == 0x233][0]
            hole.switches[0] = (0, self.local_flag_index)
            key = copy.deepcopy(hole)
            key.key += 1
            key.name = bytes(f"ItemSmallKey-{hex(key.key)[2:].upper()}", "utf-8")
            key.type = 0xa9 # small key
            key.posX = HOLE_DROP_POSITONS[room][0]
            key.posY = HOLE_DROP_POSITONS[room][1]
            key.posZ = HOLE_DROP_POSITONS[room][2]
            key.rotY = 0
            key.switches[1] = (1, self.parent.flag_manager.flags[HOLE_FLAGS[room]])
            room_data.actors.append(key)
            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.trap_models)
            room_data.setSmallKeyParams(model_path, model_name, room, item_key)
            self.writeKeyEvent(self.flow.flowchart, item_key, item_index, room)

            self.parent.file_manager.writeFile(f"{HOLE_ROOMS[room]}.leb", room_data)
            self.local_flag_index += 1


    def writeKeyEvent(self, flowchart, item_key, item_index, room):
        """Adds a new entry point to the SmallKey event flow for each key room, and inserts an ItemGetAnimation to it"""
        
        # If item is SmallKey/NightmareKey/Map/Compass/Beak/Rupee, add to inventory without any pickup animation
        if item_key[:3] in ['Sma', 'Nig', 'Dun', 'Com', 'Sto', 'Rup']:
            item_event = event_tools.createActionChain(flowchart, None, [
                ('Inventory', 'AddItemByKey', {'itemKey': item_key, 'count': 1, 'index': item_index, 'autoEquip': False})
            ], None)
        else:
            item_event = self.parent.item_get_manager.get(flowchart, item_key, item_index)

        event_tools.addEntryPoint(flowchart, room)

        event_tools.createActionChain(flowchart, room, [
            ('SmallKey', 'Deactivate', {}),
            ('SmallKey', 'SetActorSwitch', {'value': True, 'switchIndex': 1}),
            ('SmallKey', 'Destroy', {})
        ], item_event)


GRASS_ROOMS = {
    "mabe-bushes":                  "Field_11D",
    "pond-island":                  "Field_11G",
    "southwest-bay-bush":           "Field_15J",
    "beside-seashell-mansion":      "Field_09L",
    "small-coast-island":           "Field_16I"
}
GRASS_FLAGS = {
    "mabe-bushes":                  "MabeBushGet",
    "pond-island":                  "PondIslandBushGet",
    "southwest-bay-bush":           "BayBushGet",
    "beside-seashell-mansion":      "MansionBushGet",
    "small-coast-island":           "CoastIslandBushGet"
}

ROCK_ROOMS = {
    "north-of-moblin-cave":         "Field_03F",
    "desert-south":                 "Field_16P",
    "ghost-house-pot":              "GhostHouse_01A",
    "rock-maze":                    "Field_09P",
    "plains-rock-maze":             "Field_12J",
    "taltal-east-bridge":           "Field_01M",
    "taltal-west-rock":             "Field_02F"
}
ROCK_FLAGS = {
    "north-of-moblin-cave":         "MoblinCaveRockGet",
    "desert-south":                 "DesertSouthRockGet",
    "ghost-house-pot":              "GhostHousePotGet",
    "rock-maze":                    "RockMazeRockGet",
    "plains-rock-maze":             "PlainsRockGet",
    "taltal-east-bridge":           "TaltalEastRockGet",
    "taltal-west-rock":             "TaltalWestRockGet"
}

TREE_ROOMS = {
    "tail-cave-bonk-tree":          "Field_14C",
    "beach-bonk-tree":              "Field_15A",
    "ukuku-bonk-tree":              "Field_11E"
}
TREE_FLAGS = {
    "tail-cave-bonk-tree":          "TailCaveBonkTreeGet",
    "beach-bonk-tree":              "BeachBonkTreeGet",
    "ukuku-bonk-tree":              "UkukuBonkTreeGet"
}
TREE_DROP_POSITIONS = {
    "tail-cave-bonk-tree":          (36.0, 8.25, 167.0),
    "beach-bonk-tree":              (11.25, 6.0, 177.75),
    "ukuku-bonk-tree":              (70.5, 9.0, 129.0)
}

HOLE_ROOMS = {
    "taltal-heights-hole":          "Field_03N",
    "taltal-bomb-hole":             "Field_02J"
}
HOLE_FLAGS = {
    "taltal-heights-hole":          "HeightsHoleGet",
    "taltal-bomb-hole":             "BridgeHoleGet"
}
HOLE_DROP_POSITONS = {
    "taltal-heights-hole":          (192.75, 12.75, 32.25),
    "taltal-bomb-hole":             (150.75, 25.5, 12.75)
}