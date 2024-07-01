from RandomizerCore.Tools.fixed_hash import *
from RandomizerCore.Randomizers.data import MODEL_SIZES, MODEL_ROTATIONS
import re


class Actor:
    def __init__(self, data, names):
        self.names = names

        self.key = readBytes(data, 0x0, 8)
        self.name = readString(names, readBytes(data, 0x8, 4))

        if self.key != int(self.name[-16:], 16):
            raise ValueError(f'Actor key does not match for actor {hex(self.key)}')

        self.type = readBytes(data, 0xC, 2)
        self.xE = readBytes(data, 0xE, 2)
        self.roomID = readBytes(data, 0x10, 4)
        self.posX = readFloat(data, 0x14, 4)
        self.posY = readFloat(data, 0x18, 4)
        self.posZ = readFloat(data, 0x1C, 4)
        self.rotX = readFloat(data, 0x20, 4)
        self.rotY = readFloat(data, 0x24, 4)
        self.rotZ = readFloat(data, 0x28, 4)
        self.scaleX = readFloat(data, 0x2C, 4)
        self.scaleY = readFloat(data, 0x30, 4)
        self.scaleZ = readFloat(data, 0x34, 4)

        self.parameters = []
        for i in range(8):
            param_type = readBytes(data, 0x38 + (0x8 * i) + 0x4, 4)

            if param_type == 0x2:
                param = readFloat(data, 0x38 + (0x8 * i), 4)
            else:
                param = readBytes(data, 0x38 + (0x8 * i), 4)

            if param_type == 0x4:
                self.parameters.append(readString(names, param))
            else:
                self.parameters.append(param)

        self.switches = [
            (readBytes(data, 0x78, 1), readBytes(data, 0x7C, 2)),
            (readBytes(data, 0x79, 1), readBytes(data, 0x7E, 2)),
            (readBytes(data, 0x7A, 1), readBytes(data, 0x80, 2)),
            (readBytes(data, 0x7B, 1), readBytes(data, 0x82, 2))
        ]

        self.relationships = Relationship(data, names)

    def __repr__(self):
        return f'Actor: {self.name}'

    def pack(self, nameOffset):
        packed = b''
        nameRepr = self.name + b'\x00'

        packed += self.key.to_bytes(8, 'little')
        packed += nameOffset.to_bytes(4, 'little')
        packed += self.type.to_bytes(2, 'little')
        packed += self.xE.to_bytes(2, 'little')
        packed += self.roomID.to_bytes(4, 'little')
        packed += struct.pack('<f', self.posX)
        packed += struct.pack('<f', self.posY)
        packed += struct.pack('<f', self.posZ)
        packed += struct.pack('<f', self.rotX)
        packed += struct.pack('<f', self.rotY)
        packed += struct.pack('<f', self.rotZ)
        packed += struct.pack('<f', self.scaleX)
        packed += struct.pack('<f', self.scaleY)
        packed += struct.pack('<f', self.scaleZ)

        for i in range(8):
            param = self.parameters[i]
            if isinstance(param, bytes):
                packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
                packed += (4).to_bytes(4, 'little')
                nameRepr += param + b'\x00'
            elif isinstance(param, float):
                packed += struct.pack('<f', param)
                packed += (2).to_bytes(4, 'little')
            else:
                packed += param.to_bytes(4, 'little')
                packed += (3).to_bytes(4, 'little')

        switches = b''
        for i in range(4):
            packed += self.switches[i][0].to_bytes(1, 'little')
            switches += self.switches[i][1].to_bytes(2, 'little')
        packed += switches

        packed += self.relationships.pack(nameRepr, nameOffset)

        return packed


    def display(self):
        print(f'Name: {self.name}')
        print(f'Type: {self.type}')
        print(f'Room ID: {self.roomID}')
        print(f'Coordinates: {self.posX}, {self.posY}, {self.posZ}')
        print(f'Parameters: {self.parameters}')


    def positionToPoint(self):
        packed = b''
        packed += struct.pack('<f', self.posX)
        packed += struct.pack('<f', self.posY)
        packed += struct.pack('<f', self.posZ)
        packed += b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
        
        return packed



class Room:
    def __init__(self, data, edit_grid=False):
        self.fixed_hash = FixedHash(data)

        # self.points = []
        # point_entry = [e for e in self.fixed_hash.entries if e.name == b'point'][0]
        # for entry in point_entry.data.entries:
        # 	self.points.append(Point(entry.data))

        # self.rails = []
        # rail_entry = [e for e in self.fixed_hash.entries if e.name == b'rail'][0]
        # for entry in rail_entry.data.entries:
        # 	self.rails.append(Rail(data=entry.data, names=self.fixed_hash.namesSection))

        self.actors = []
        actor_entry = [e for e in self.fixed_hash.entries if e.name == b'actor'][0]
        for entry in actor_entry.data.entries:
            self.actors.append(Actor(entry.data, self.fixed_hash.namesSection))

        if edit_grid:
            try:
                grid_entry = [e for e in self.fixed_hash.entries if e.name == b'grid'][0]
                self.grid = Grid(grid_entry)
            except IndexError:
                self.grid = None
        else:
            self.grid = None


    def setChestContent(self, new_content, item_index, chest_index=0, chest_size=1.0, chest_model=None):
        chests = [a for a in self.actors if a.type == 0xF7]

        if len(chests) > chest_index:
            chest = chests[chest_index]
            chest.parameters[1] = bytes(new_content, 'utf-8')
            chest.parameters[2] = item_index if item_index != -1 else b''

            if chest_model != None:
                chest.parameters[6] = bytes(chest_model, 'utf-8')
                chest.parameters[7] = bytes('TreasureBox', 'utf-8')

            chest.scaleX = chest_size
            chest.scaleY = chest_size
            chest.scaleZ = chest_size
        
        # if item_key == 'BowWow':
        #     pass
        # elif item_key == 'Rooster':
        #     room_data.addChestRooster()


    def setSmallKeyParams(self, model_path, model_name, room, item_key, key_index=0):
        keys = [a for a in self.actors if a.type == 0xA9]

        if len(keys) > key_index:
            key = keys[key_index]

            # key.type = 0x88 # GoldenLeaf
            key.parameters[1] = bytes(model_path, 'utf-8')
            key.parameters[2] = bytes(model_name, 'utf-8')
            key.parameters[3] = bytes(room, 'utf-8')

            if item_key == 'Seashell':
                key.parameters[4] = bytes('true', 'utf-8')
            else:
                key.parameters[4] = bytes('false', 'utf-8')
            
            if model_name in MODEL_SIZES:
                size = MODEL_SIZES[model_name]
                key.scaleX = size
                key.scaleY = size
                key.scaleZ = size
            if model_name in MODEL_ROTATIONS:
                key.rotY = MODEL_ROTATIONS[model_name]
    

    def setRupeeParams(self, model_path, model_name, entry_point, item_key, rup_index=0):
        rups = [a for a in self.actors if a.type == 0xAB]

        if len(rups) > 0:
            rup = rups[0] # since we are changing the type, the list of rupees gets smaller, therefore we just get the first rup
            rup.type = 0x194 # sinking sword
            rup.parameters[0] = bytes(model_path, 'utf-8')
            rup.parameters[1] = bytes(model_name, 'utf-8')
            rup.parameters[2] = bytes(entry_point, 'utf-8')
            rup.parameters[3] = bytes('Lv10RupeeGet' if rup_index == 0 else f'Lv10RupeeGet_{rup_index + 1}', 'utf-8')

            if item_key == 'Seashell':
                rup.parameters[4] = bytes('true', 'utf-8')
            else:
                rup.parameters[4] = bytes('false', 'utf-8')
            
            if model_name in MODEL_SIZES:
                size = MODEL_SIZES[model_name]
                rup.scaleX = size
                rup.scaleY = size
                rup.scaleZ = size
            if model_name in MODEL_ROTATIONS:
                rup.rotY = MODEL_ROTATIONS[model_name]
    

    def setLoadingZoneTarget(self, new_destination, index=0):
        zones = [a for a in self.actors if a.type == 0x190]

        if len(zones) > index:
            zone = zones[index]
            zone.parameters[0] = bytes(re.match('(.+)_\\d\\d[A-Z]', new_destination).group(1), 'utf-8')
            zone.parameters[1] = bytes(new_destination, 'utf-8')


    def repack(self):
        new_names = b''

        for entry in self.fixed_hash.entries:
            # if entry.name == b'point':
            # 	entry.data.entries = []
            # 	for point in self.points:
            # 		# Create a new point entry for actors to use
            # 		entry.data.entries.append(Entry(0xFFF3, b'', 0xFFFFFFFF, point.pack()))

            # if entry.name == b'rail':
            # 	entry.data.entries = []
            # 	for rail in self.rails:
            # 		# Create a new rail entry to reference point indexes per rail
            # 		entry.data.entries.append(Entry(0xFFF2, b'', 0xFFFFFFFF, rail.pack(len(new_names))))

            # 		for param in rail.xC:
            # 			if isinstance(param, bytes):
            # 				new_names += param + b'\x00'

            if entry.name == b'actor':
                entry.data.entries = []
                for actor in self.actors:
                    # Create a new entry for the actor in the actors FixedHash, using a newly packed data block for that actor
                    entry.data.entries.append(Entry(0xFFF0, b'', 0xFFFFFFFF, actor.pack(len(new_names))))

                    new_names += actor.name + b'\x00'

                    for param in actor.parameters:
                        if isinstance(param, bytes):
                            new_names += param + b'\x00'

                    for s1 in actor.relationships.section_1:
                        if isinstance(s1[0][0], bytes):
                            new_names += s1[0][0] + b'\x00'
                        if isinstance(s1[0][1], bytes):
                            new_names += s1[0][1] + b'\x00'

                    for s2 in actor.relationships.section_2:
                        if isinstance(s2[0][0], bytes):
                            new_names += s2[0][0] + b'\x00'
                        if isinstance(s2[0][1], bytes):
                            new_names += s2[0][1] + b'\x00'

            if entry.name == b'grid' and self.grid != None:
                entry.data.entries = []
                entry.data.entries.append(Entry(0xFFF0, b'data', 0xFFFFFFFF, self.grid.pack()))
                # new_names += b'data' + b'\x00'

                if self.grid.chain_entry != None:
                    entry.data.entries.append(Entry(0xFFF0, b'chain', 0xFFFFFFFF, self.grid.chain_entry.data))
                    # new_names += b'chain' + b'\x00'

                entry.data.entries.append(Entry(0xFFF0, b'info', 0x0, self.grid.info.pack()))
                # new_names += b'info' + b'\x00'

            new_names += entry.name + b'\x00'

        self.fixed_hash.namesSection = new_names

        return self.fixed_hash.toBinary()



class Relationship:
    def __init__(self, data, names):
        self.e = readBytes(data, 0x84, 1)
        self.k = readBytes(data, 0x85, 1)
        self.b = readBytes(data, 0x86, 1)
        self.x = readBytes(data, 0x87, 1)
        self.y = readBytes(data, 0x88, 1)
        self.z = readBytes(data, 0x89, 1)

        self.null = data[0x8A:0x90]

        self.section_1 = []
        self.section_2 = []
        self.section_3 = []

        pos = 0x90

        for i in range(self.x):
            acts = []
            seq = []

            for b in range(2):
                param_type = readBytes(data, pos + (0x8 * b) + 0x4, 4)

                if param_type == 0x2:
                    param = readFloat(data, pos + (0x8 * b), 4)
                else:
                    param = readBytes(data, pos + (0x8 * b), 4)

                if param_type == 0x4:
                    seq.append(readString(names, param))
                else:
                    seq.append(param)

            act_index = readBytes(data, pos + 0x10, 4)
            acts.append(seq)
            acts.append(act_index)
            self.section_1.append(acts)
            pos += 20

        for i in range(self.z):
            acts = []
            seq = []

            for b in range(2):
                param_type = readBytes(data, pos + (0x8 * b) + 0x4, 4)

                if param_type == 0x2:
                    param = readFloat(data, pos + (0x8 * b), 4)
                else:
                    param = readBytes(data, pos + (0x8 * b), 4)

                if param_type == 0x4:
                    seq.append(readString(names, param))
                else:
                    seq.append(param)

            rail = readBytes(data, pos + 0x10, 4)
            point = readBytes(data, pos + 0x14, 4)
            acts.append(seq)
            acts.append(rail)
            acts.append(point)
            self.section_2.append(acts)
            pos += 24

        for i in range(self.y):
            id = readBytes(data, pos + (0x4 * i), 4)
            self.section_3.append(id)


    def pack(self, nameRepr, nameOffset):
        packed = b''
        packed += self.e.to_bytes(1, 'little')
        packed += self.k.to_bytes(1, 'little')
        packed += self.b.to_bytes(1, 'little')
        packed += self.x.to_bytes(1, 'little')
        packed += self.y.to_bytes(1, 'little')
        packed += self.z.to_bytes(1, 'little')
        packed += self.null

        for i in range(self.x):
            param1 = self.section_1[i][0][0]
            param2 = self.section_1[i][0][1]
            act_index = self.section_1[i][1]

            if isinstance(param1, bytes):
                packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
                packed += (4).to_bytes(4, 'little')
                nameRepr += param1 + b'\x00'
            elif isinstance(param1, float):
                packed += struct.pack('<f', param1)
                packed += (2).to_bytes(4, 'little')
            else:
                packed += param1.to_bytes(4, 'little')
                packed += (3).to_bytes(4, 'little')

            if isinstance(param2, bytes):
                packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
                packed += (4).to_bytes(4, 'little')
                nameRepr += param2 + b'\x00'
            elif isinstance(param2, float):
                packed += struct.pack('<f', param2)
                packed += (2).to_bytes(4, 'little')
            else:
                packed += param2.to_bytes(4, 'little')
                packed += (3).to_bytes(4, 'little')

            packed += act_index.to_bytes(4, 'little')

        for i in range(self.z):
            param1 = self.section_2[i][0][0]
            param2 = self.section_2[i][0][1]
            rail = self.section_2[i][1]
            point = self.section_2[i][2]

            if isinstance(param1, bytes):
                packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
                packed += (4).to_bytes(4, 'little')
                nameRepr += param1 + b'\x00'
            elif isinstance(param1, float):
                packed += struct.pack('<f', param1)
                packed += (2).to_bytes(4, 'little')
            else:
                packed += param1.to_bytes(4, 'little')
                packed += (3).to_bytes(4, 'little')

            if isinstance(param2, bytes):
                packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
                packed += (4).to_bytes(4, 'little')
                nameRepr += param2 + b'\x00'
            elif isinstance(param2, float):
                packed += struct.pack('<f', param2)
                packed += (2).to_bytes(4, 'little')
            else:
                packed += param2.to_bytes(4, 'little')
                packed += (3).to_bytes(4, 'little')

            packed += rail.to_bytes(4, 'little')
            packed += point.to_bytes(4, 'little')

        for i in range(self.y):
            packed += self.section_3[i].to_bytes(4, 'little')

        return packed



# # EXPERIMENTAL POINT AND RAIL SECTIONS
# class Point:
# 	def __init__(self, data):
# 			self.posX = readFloat(data, 0x0, 4)
# 			self.posY = readFloat(data, 0x4, 4)
# 			self.posZ = readFloat(data, 0x8, 4)
# 			self.xC = data[0xC:]

# 	def pack(self):
# 		packed = b''
# 		packed += struct.pack('<f', self.posX)
# 		packed += struct.pack('<f', self.posY)
# 		packed += struct.pack('<f', self.posZ)
# 		packed += self.xC

# 		return packed



# class Rail:
# 	def __init__(self, data=None, points=None, names=None):
# 		if data is not None:
# 			self.x0 = data[0x0:0xC]

# 			self.xC = []
# 			for i in range(4):
# 				paramType = readBytes(data, 0xC + (0x8 * i) + 0x4, 4)

# 				if paramType == 0x2:
# 					param = readFloat(data, 0xC + (0x8 * i), 4)
# 				else:
# 					param = readBytes(data, 0xC + (0x8 * i), 4)

# 				if paramType == 0xFFFFFF04:
# 					self.xC.append(readString(names, param))
# 				else:
# 					self.xC.append(param)

# 			self.num_entries = readBytes(data, 0x2C, 2)
# 			self.num_indexes = readBytes(data, 0x2E, 2)

# 			self.points = []
# 			for i in range(self.num_entries):
# 				self.points.append(readBytes(data, (0x30 + (0x2 * i)), 2))

# 		else:
# 			self.x0 = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
# 			self.xC = [25, 25, 25, 25]
# 			self.num_entries = len(points)
# 			self.num_indexes = 0x1
# 			self.points = points


# 	def pack(self, nameOffset):
# 		packed = b''
# 		packed += self.x0

# 		nameRepr = b'' # + b'\x00'

# 		for i in range(4):
# 			param = self.xC[i]
# 			if isinstance(param, bytes):
# 				packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
# 				packed += (0xFFFFFF04).to_bytes(4, 'little')
# 				nameRepr += param + b'\x00'
# 			elif isinstance(param, float):
# 				packed += struct.pack('<f', param)
# 				packed += (2).to_bytes(4, 'little')
# 			else:
# 				packed += param.to_bytes(4, 'little')
# 				packed += (3).to_bytes(4, 'little')

# 		packed += self.num_entries.to_bytes(2, 'little')
# 		packed += self.num_indexes.to_bytes(2, 'little')

# 		for i in range(self.num_entries):
# 			packed += self.points[i].to_bytes(2, 'little')

# 		return packed



# EXPERIMENTAL GRID SECTION
class Grid:
    def __init__(self, entry):
        self.chain_entry = None

        for e in entry.data.entries:
            if e.name == b'data':
                self.data_entry = e
                continue
            if e.name == b'chain':
                self.chain_entry = e
                continue
            if e.name == b'info':
                self.info = self.InfoBlock(e.data)

        if self.info.room_height not in (8, 2):
            raise ValueError('Cannot determine room type')

        self.tilesdata = []
        if self.info.room_height == 8:
            for i in range(80): # top-down room
                start_addr = (0x10 * i)
                self.tilesdata.append(self.TileData(self.data_entry.data[start_addr : (start_addr + 0x10)]))
        else:
            for i in range(20): # sidescroller room
                start_addr = (0x10 * i)
                self.tilesdata.append(self.TileData(self.data_entry.data[start_addr : (start_addr + 0x10)]))


    def pack(self): # this handles packing of just the data entry
        packed = b''
        for tile in self.tilesdata:
            packed += tile.pack()

        return packed



    class TileData:
        def __init__(self, data):
            flags_byte = readBytes(data, 0x0, 1)
            self.flags1 = {
                'southcollision': 1 if flags_byte&128 != 0 else 0,
                'unused6': 1 if flags_byte&64 != 0 else 0,
                'eastcollision': 1 if flags_byte&32 != 0 else 0,
                'unused4': 1 if flags_byte&16 != 0 else 0,
                'northcollision': 1 if flags_byte&8 != 0 else 0,
                'unused2': 1 if flags_byte&4 != 0 else 0,
                'containscollision': 1 if flags_byte&2 != 0 else 0,
                'deepwaterlava': 1 if flags_byte&1 != 0 else 0
            }

            flags_byte = readBytes(data, 0x1, 1)
            self.flags2 = {
                'unused7': 1 if flags_byte&128 != 0 else 0,
                'unused6': 1 if flags_byte&64 != 0 else 0,
                'unused5': 1 if flags_byte&32 != 0 else 0,
                'unused4': 1 if flags_byte&16 != 0 else 0,
                'unused3': 1 if flags_byte&8 != 0 else 0,
                'unused2': 1 if flags_byte&4 != 0 else 0,
                'westcollision': 1 if flags_byte&2 != 0 else 0,
                'unused0': 1 if flags_byte&1 != 0 else 0
            }

            flags_byte = readBytes(data, 0x2, 1)
            self.flags3 = {
                'unused7': 1 if flags_byte&128 != 0 else 0,
                'unknown6': 1 if flags_byte&64 != 0 else 0,
                'canrefresh': 1 if flags_byte&32 != 0 else 0,
                'respawnload': 1 if flags_byte&16 != 0 else 0,
                'respawnvoid': 1 if flags_byte&8 != 0 else 0,
                'iswaterlava': 1 if flags_byte&4 != 0 else 0,
                'unused1': 1 if flags_byte&2 != 0 else 0,
                'isdigspot': 1 if flags_byte&1 != 0 else 0
            }

            flags_byte = readBytes(data, 0x3, 1)
            self.flags4 = {
                'unused7': 1 if flags_byte&128 != 0 else 0,
                'unused6': 1 if flags_byte&64 != 0 else 0,
                'unused5': 1 if flags_byte&32 != 0 else 0,
                'unused4': 1 if flags_byte&16 != 0 else 0,
                'unused3': 1 if flags_byte&8 != 0 else 0,
                'unused2': 1 if flags_byte&4 != 0 else 0,
                'unused1': 1 if flags_byte&2 != 0 else 0,
                'unused0': 1 if flags_byte&1 != 0 else 0
            }

            # self.unknown = data[0x4:0x8] # matches the first 4 bytes

            self.chain_index = readBytes(data, 0x8, 4)
            self.elevation = readFloat(data, 0xC, 4)


        def pack(self):
            packed = b''

            bin_str1 = ''.join(str(i) for i in list(self.flags1.values()))
            packed += int(bin_str1, 2).to_bytes(1, 'little')

            bin_str2 = ''.join(str(i) for i in list(self.flags2.values()))
            packed += int(bin_str2, 2).to_bytes(1, 'little')

            bin_str3 = ''.join(str(i) for i in list(self.flags3.values()))
            packed += int(bin_str3, 2).to_bytes(1, 'little')

            bin_str4 = ''.join(str(i) for i in list(self.flags4.values()))
            packed += int(bin_str4, 2).to_bytes(1, 'little')

            # packed += self.unknown

            # having this match the first 4 bytes is important for the tile properties to work properly
            packed += int(bin_str1, 2).to_bytes(1, 'little')
            packed += int(bin_str2, 2).to_bytes(1, 'little')
            packed += int(bin_str3, 2).to_bytes(1, 'little')
            packed += int(bin_str4, 2).to_bytes(1, 'little')

            packed += self.chain_index.to_bytes(4, 'little')
            packed += struct.pack('<f', self.elevation)

            return packed



    class InfoBlock:
        def __init__(self, data):
            self.room_height = readBytes(data, 0x0, 2)
            self.room_width = readBytes(data, 0x2, 2)
            self.tile_size = readFloat(data, 0x4, 4)
            self.x_coord = readFloat(data, 0x8, 4)
            self.z_coord = readFloat(data, 0xC, 4)

        def pack(self):
            packed = b''
            packed += self.room_height.to_bytes(2, 'little')
            packed += self.room_width.to_bytes(2, 'little')
            packed += struct.pack('<f', self.tile_size)
            packed += struct.pack('<f', self.x_coord)
            packed += struct.pack('<f', self.z_coord)

            return packed
