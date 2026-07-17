import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers.data import MODEL_SIZES, MODEL_ROTATIONS
import copy


class SeashellRandomizer:
    def __init__(self, mod_generator) -> None:
        self.parent = mod_generator

        self.flow = self.parent.file_manager.readFile('SmallKey.bfevfl')

        # we are using local flags to spawn stuff the items
        # this is because we want them to keep the bahavior where they despawn if you leave
        # Field looks to use around 80 local flags, all being gravestones or grass with holes under them
        # I believe local flags range from 0-255, so we will try starting at 101
        self.local_flag_index = 101

        self.addBushDrops()
        self.addRockDrops()
        self.addTreeDrops()
        self.addHoleDrops()

        self.parent.file_manager.writeFile('SmallKey.bfevfl', self.flow)

        self.randomizeStaticShells()


    def addBushDrops(self) -> None:
        for room in GRASS_ROOMS:
            if not self.parent.thread_active:
                break

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
            self.writeKeyEvent(self.flow.flowchart, room)

            self.parent.file_manager.writeFile(f"{GRASS_ROOMS[room]}.leb", room_data)
            self.local_flag_index += 1


    def addRockDrops(self) -> None:
        for room in ROCK_ROOMS:
            if not self.parent.thread_active:
                break

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
            self.writeKeyEvent(self.flow.flowchart, room)

            self.parent.file_manager.writeFile(f"{ROCK_ROOMS[room]}.leb", room_data)
            self.local_flag_index += 1


    def addTreeDrops(self) -> None:
        """Adds small keys where the item in the tree would land

        We use exlaunch to force the tree to set its switch0 when bonked"""

        for room in TREE_ROOMS:
            if not self.parent.thread_active:
                break

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
            self.writeKeyEvent(self.flow.flowchart, room)

            self.parent.file_manager.writeFile(f"{TREE_ROOMS[room]}.leb", room_data)
            self.local_flag_index += 1


    def addHoleDrops(self) -> None:
        for room in HOLE_ROOMS:
            if not self.parent.thread_active:
                break

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
            self.writeKeyEvent(self.flow.flowchart, room)

            self.parent.file_manager.writeFile(f"{HOLE_ROOMS[room]}.leb", room_data)
            self.local_flag_index += 1


    def writeKeyEvent(self, flowchart, room) -> None:
        """Adds a new entry point to the SmallKey event flow for each key room, and inserts an ItemGetAnimation to it"""
        
        item_event = self.parent.item_get_manager.get(flowchart, room)

        event_tools.addEntryPoint(flowchart, room)

        event_tools.createActionChain(flowchart, room, [
            ('SmallKey', 'Deactivate', {}),
            ('SmallKey', 'SetActorSwitch', {'value': True, 'switchIndex': 1}),
            ('SmallKey', 'Destroy', {})
        ], item_event)


    def randomizeStaticShells(self) -> None:
        flow = self.parent.file_manager.readFile('SinkingSword.bfevfl')

        for room in SHELL_ROOMS:
            if not self.parent.thread_active:
                break

            item_key, item_index, model_path, model_name = self.parent.item_info_manager.getItemInfoWithModel(room, self.parent.trap_models)
            room_data = self.parent.file_manager.readFile(f"{SHELL_ROOMS[room]}.leb")
            shells = [a for a in room_data.actors if a.type == 0x87]
            if len(shells) > 0:
                shell = shells[0]
                shell.type = 0x8a # turn shells into ItemSlimeKey actors
            else:
                shell = [a for a in room_data.actors if a.type == 0x8a][0] # slime key

            get_anim = self.parent.item_get_manager.get(flow.flowchart, room)

            event_tools.addEntryPoint(flow.flowchart, room)
            event_tools.createActionChain(flow.flowchart, room, [
                ('SinkingSword', 'Destroy', {}),
                ('EventFlags', 'SetFlag', {'symbol': SHELL_FLAGS[room], 'value': True})
            ], get_anim)

            # sunken seashells will be changed into heart piece actors
            # heart piece actors are bigger and easier to see without manually figuring out scale
            if room in ("kanalet-moat-north", "taltal-sunken"):
                shell.type = 0xB0
                if model_name not in ("HeartPiece", "HeartContainer"):
                    shell.posY += 0.25 # raise them up 1/6 of a tile
                    shell.scaleX = 0.75
                    shell.scaleY = 0.75
                    shell.scaleZ = 0.75

            # could be ItemSlimeKey or ItemHeartPiece actor, so we can't use parameter[0] as that is index for HPs
            shell.parameters[1] = bytes(model_path, 'utf-8')
            shell.parameters[2] = bytes(model_name, 'utf-8')
            shell.parameters[3] = bytes(room, 'utf-8') # entry point
            shell.parameters[4] = bytes(SHELL_FLAGS[room], 'utf-8') # flag which controls if the shell appears or not

            if item_key == 'Seashell':
                shell.parameters[5] = bytes('true', 'utf-8')
            else:
                shell.parameters[5] = bytes('false', 'utf-8')

            if model_name in MODEL_SIZES:
                size = MODEL_SIZES[model_name]
                shell.scaleX = size
                shell.scaleY = size
                shell.scaleZ = size
            if model_name in MODEL_ROTATIONS:
                shell.rotY = MODEL_ROTATIONS[model_name]

            self.parent.file_manager.writeFile(f"{SHELL_ROOMS[room]}.leb", room_data)

        self.parent.file_manager.writeFile('SinkingSword.bfevfl', flow)


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

SHELL_ROOMS = {
    "kanalet-moat-north":           "Field_04I",
    "taltal-sunken":                "Field_02M",
    "south-bay-dig":                "Field_14K",
    "beach-dig":                    "Field_16F",
    "wasteland-dig":                "Field_05H",
    "desert-dig":                   "Field_13P",
    "ghost-grave-dig":              "Field_08E",
    "doghouse-dig":                 "DogHouse_01A",
    "goponga-west-dig":             "Field_03B",
    "above-cave-dig":               "Field_11I",
    "above-d3":                     "Field_11F",
    "under-skull-rock":             "Field_10H",
    "rapids-east-island":           "Field_06O",
    "taltal-west-dig":              "Field_02C",
    "woods-west-dig":               "Field_05A",
    "woods-east-dig":               "Field_06C",
    "pothole-final":                "Field_13G" # we treat the slime key spot as a seashell
}
SHELL_FLAGS = {
    "kanalet-moat-north":           "KanaletSunkenShellGet",
    "taltal-sunken":                "TaltalSunkenShellGet",
    "south-bay-dig":                "SouthBayDigShellGet",
    "beach-dig":                    "BeachDigShellGet",
    "wasteland-dig":                "WastelandDigShellGet",
    "desert-dig":                   "DesertDigShellGet",
    "ghost-grave-dig":              "GhostGraveDigShellGet",
    "doghouse-dig":                 "DoghouseDigShellGet",
    "goponga-west-dig":             "GopongaDigShellGet",
    "above-cave-dig":               "AboveCaveDigShellGet",
    "above-d3":                     "AboveD3DigShellGet",
    "under-skull-rock":             "UnderSkullDigShellGet",
    "rapids-east-island":           "RapidsEastDigShellGet",
    "taltal-west-dig":              "TaltalWestDigShellGet",
    "woods-west-dig":               "WoodsWestDigShellGet",
    "woods-east-dig":               "WoodsEastDigShellGet",
    "pothole-final":                "PotholeItemGetFlag"
}