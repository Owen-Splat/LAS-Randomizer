import struct
import copy
import re


def readBytes(bytes, start, length, endianness='little'):
	return int.from_bytes(bytes[start : start + length], endianness)

def readFloat(bytes, start, length):
	return float(struct.unpack('<f', bytes[start : start + length])[0])

def readString(data, start):
	result = b''
	index = start

	while index < len(data) and data[index]:
		result += data[index : index + 1]
		index += 1

	return result

def hash_string(s):
    data = s + b"\x00"
    h = 0
    i = 0
    while data[i]:
        h ^= (data[i] + (h >> 2) + (h << 5)) & 0xFFFFFFFF
        i += 1
    return h



class Entry:
	def __init__(self, nodeIndex, name, nextOffset, data):
		self.nodeIndex = nodeIndex
		self.name = name
		self.nextOffset = nextOffset
		self.data = data



class FixedHash:
	def __init__(self, data, offset=0):
		self.magic = readBytes(data, offset + 0x0, 1)
		self.version = readBytes(data, offset + 0x1, 1)
		self.numBuckets = readBytes(data, offset + 0x2, 2)
		self.numNodes = readBytes(data, offset + 0x4, 2)
		self.x6 = readBytes(data, offset + 0x6, 2)

		self.buckets = []
		for i in range(self.numBuckets): # there will be an extra one. I don't really know what this data means but we want to preserve it
			self.buckets.append(readBytes(data, offset + 0x8 + (i * 4), 4))

		entriesOffset = ((offset + 0x8 + 4*(self.numBuckets+1) + 3) & -8) + 8
		numEntries = readBytes(data, entriesOffset - 8, 8) // 0x10

		entryOffsetsOffset = entriesOffset + (numEntries * 0x10) + 8

		dataSectionOffset = ((entryOffsetsOffset + (4 * numEntries) + 7) & -8) + 8

		namesSectionOffset = ((dataSectionOffset + readBytes(data, dataSectionOffset - 8, 8) + 3) & -4) + 4
		namesSize = readBytes(data, namesSectionOffset - 4, 4)
		self.namesSection = data[namesSectionOffset : namesSectionOffset + namesSize]

		self.entries = []
		for i in range(numEntries):
			currentOffset = entriesOffset + (i * 0x10)
			
			nodeIndex = readBytes(data, currentOffset, 2)
			
			nextOffset = readBytes(data, currentOffset + 8, 4)
			
			if namesSize:
				name = readString(data, namesSectionOffset + readBytes(data, currentOffset + 2, 2))
			else:
				name = b''

			entryDataOffset = readBytes(data, currentOffset + 0xC, 4)
			
			if nodeIndex <= 0xFFED:
				entryData = FixedHash(data, dataSectionOffset + entryDataOffset)
				#print(data[dataSectionOffset + entryDataOffset : dataSectionOffset + entryDataOffset + 32])
				pass
			elif nodeIndex >= 0xFFF0:
				dataSize = readBytes(data, dataSectionOffset + entryDataOffset, 8)
				
				entryData = data[dataSectionOffset + entryDataOffset + 8 : dataSectionOffset + entryDataOffset + 8 + dataSize]
			else:
				raise ValueError('Invalid node index')

			self.entries.append(Entry(nodeIndex, name, nextOffset, entryData))

	def toBinary(self, offset=0):
		# Returns a bytes object of the fixed hash in binary form
		intro = b''

		intro += self.magic.to_bytes(1, 'little')
		intro += self.version.to_bytes(1, 'little')
		intro += self.numBuckets.to_bytes(2, 'little')
		intro += self.numNodes.to_bytes(2, 'little')
		intro += self.x6.to_bytes(2, 'little')

		for bucket in self.buckets:
			intro += bucket.to_bytes(4, 'little')

		entriesSect = (len(self.entries) * 0x10).to_bytes(8, 'little')
		entryOffsetsSect = (len(self.entries) * 0x4).to_bytes(8, 'little')
		dataSect = b''
		
		for i in range(len(self.entries)):
			entry = self.entries[i]

			entriesSect += entry.nodeIndex.to_bytes(2, 'little')
			if self.namesSection.count(entry.name) and self.namesSection != b'':
				entriesSect += self.namesSection.index(entry.name + b'\x00').to_bytes(2, 'little')
			else:
				entriesSect += b'\x00\x00'
			entriesSect += hash_string(entry.name).to_bytes(4, 'little')
			entriesSect += entry.nextOffset.to_bytes(4, 'little')
			entriesSect += len(dataSect).to_bytes(4, 'little')
			
			entryOffsetsSect += (i * 0x10).to_bytes(4, 'little')

			if entry.nodeIndex <= 0xFFED:
				dataSect += entry.data.toBinary(len(dataSect))
			elif entry.nodeIndex >= 0xFFF0:
				dataSect += len(entry.data).to_bytes(8, 'little') + entry.data

				dataSect += b'\x00\x00\x00\x00\x00\x00\x00'
				dataSect = dataSect[:len(dataSect) & -8]
			else:
				raise ValueError('Invalid node index')

		dataSect = len(dataSect).to_bytes(8, 'little') + dataSect

		result = b''
		result += intro

		if (len(result) + offset) % 8 != 0:
			result += b'\x00\x00\x00\x00' # Pad with 4 null bytes if it's not at a multiple of 8
		result += entriesSect

		if (len(result) + offset) % 8 != 0:
			result += b'\x00\x00\x00\x00'
		result += entryOffsetsSect

		if (len(result) + offset) % 8 != 0:
			result += b'\x00\x00\x00\x00'
		result += dataSect

		while (len(result) + offset) % 4 != 0:
			result += b'\x00'
		result += len(self.namesSection).to_bytes(4, 'little')
		result += self.namesSection

		return result



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
			param = readBytes(data, 0x38 + (0x8 * i), 4)
			paramType = readBytes(data, 0x38 + (0x8 * i) + 0x4, 4)

			if paramType == 0x4:
				self.parameters.append(readString(names, param))
			else:
				self.parameters.append(param)

		self.switches = [
			(readBytes(data, 0x78, 1), readBytes(data, 0x7C, 2)),
			(readBytes(data, 0x79, 1), readBytes(data, 0x7E, 2)),
			(readBytes(data, 0x7A, 1), readBytes(data, 0x80, 2)),
			(readBytes(data, 0x7B, 1), readBytes(data, 0x82, 2))
		]
		
		# self.x84 = data[0x84:]
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
			else:
				packed += param.to_bytes(4, 'little')
				packed += (3).to_bytes(4, 'little')

		switches = b''
		for i in range(4):
			packed += self.switches[i][0].to_bytes(1, 'little')
			switches += self.switches[i][1].to_bytes(2, 'little')
		packed += switches
		
		# packed += self.x84 # relationship data but it's unfinished so we just keep the data as is for now

		packed += self.relationships.e.to_bytes(1, 'little')
		packed += self.relationships.k.to_bytes(1, 'little')
		packed += self.relationships.b.to_bytes(1, 'little')
		packed += self.relationships.x.to_bytes(1, 'little')
		packed += self.relationships.y.to_bytes(1, 'little')
		packed += self.relationships.z.to_bytes(1, 'little')
		packed += self.relationships.null

		for i in range(self.relationships.x):
			param1 = self.relationships.section_1[i][0][0]
			param2 = self.relationships.section_1[i][0][1]
			act_index = self.relationships.section_1[i][1]

			if isinstance(param1, bytes):
				packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
				packed += (4).to_bytes(4, 'little')
				nameRepr += param1 + b'\x00'
			else:
				packed += param1.to_bytes(4, 'little')
				packed += (3).to_bytes(4, 'little')
			
			if isinstance(param2, bytes):
				packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
				packed += (4).to_bytes(4, 'little')
				nameRepr += param2 + b'\x00'
			else:
				packed += param2.to_bytes(4, 'little')
				packed += (3).to_bytes(4, 'little')
			
			packed += act_index.to_bytes(4, 'little')
		
		for i in range(self.relationships.z):
			param1 = self.relationships.section_2[i][0][0]
			param2 = self.relationships.section_2[i][0][1]
			rail = self.relationships.section_2[i][1]
			point = self.relationships.section_2[i][2]

			if isinstance(param1, bytes):
				packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
				packed += (4).to_bytes(4, 'little')
				nameRepr += param1 + b'\x00'
			else:
				packed += param1.to_bytes(4, 'little')
				packed += (3).to_bytes(4, 'little')
			
			if isinstance(param2, bytes):
				packed += (len(nameRepr) + nameOffset).to_bytes(4, 'little')
				packed += (4).to_bytes(4, 'little')
				nameRepr += param2 + b'\x00'
			else:
				packed += param2.to_bytes(4, 'little')
				packed += (3).to_bytes(4, 'little')
			
			packed += rail.to_bytes(4, 'little')
			packed += point.to_bytes(4, 'little')
		
		if self.relationships.y > 0:
			for i in range(self.relationships.y):
				packed += self.relationships.section_3[i].to_bytes(4, 'little')

		return packed


	def display(self):
		print(f'Name: {self.name}')
		print(f'Type: {self.type}')
		print(f'Room ID: {self.roomID}')
		print(f'Coordinates: {self.posX}, {self.posY}, {self.posZ}')
		print(f'Parameters: {self.parameters}')



class Room:
	def __init__(self, data):
		self.fixed_hash = FixedHash(data)

		self.actors = []
		actor_entry = [e for e in self.fixed_hash.entries if e.name == b'actor'][0]
		for entry in actor_entry.data.entries:
			self.actors.append(Actor(entry.data, self.fixed_hash.namesSection))
		
		# grid_entry = [e for e in self.fixed_hash.entries if e.name == b'grid'][0]
		# self.grid = Grid(grid_entry)


	def setChestContent(self, new_content, item_index, chest_index=0):
		chests = [a for a in self.actors if a.type == 0xF7]

		if len(chests) > chest_index:
			chest = chests[chest_index]
			chest.parameters[1] = bytes(new_content, 'utf-8')
			chest.parameters[2] = item_index if item_index != -1 else b''
	

	def addChestRooster(self, chest_index=0):
		chests = [a for a in self.actors if a.type == 0xF7]

		if len(chests) > chest_index:
			chest = chests[chest_index]
			new_actor = copy.deepcopy(chest)

			chest.relationships.x += 1
			chest.relationships.section_1.append([[b'', b''], len(self.actors)])

			name_hex = f'A1000{chest_index}005D1D906E'
			new_actor.key = int(name_hex, 16)
			new_actor.name = bytes(f'NpcFlyingCucco-{name_hex}', 'utf-8')
			new_actor.type = 0x181
			new_actor.parameters = [0, b'FlyCocco', b'', b'', b'', b'', b'', b'']
			new_actor.relationships.y += 1
			new_actor.relationships.section_3.append(self.actors.index(chest))
			self.actors.append(new_actor)
	

	# def addShadowTrap(self, chest_index=0):
	# 	chests = [a for a in self.actors if a.type == 0xF7]

	# 	if len(chests) > chest_index:
	# 		chest = chests[chest_index]
	# 		new_actor = copy.deepcopy(chest)

	# 		chest.relationships.x += 1
	# 		chest.relationships.section_1.append([[b'', b''], len(self.actors)])

	# 		name_hex = f'A1000{chest_index}006E2E017F'
	# 		new_actor.key = int(name_hex, 16)
	# 		new_actor.name = bytes(f'PanelShadowLink-{name_hex}', 'utf-8')
	# 		new_actor.type = 0x21E
	# 		# new_actor.posZ += 3 # move 2 tiles south of chest to appear behind the player
	# 		new_actor.parameters = [b'Appear', b'', b'', b'', b'', b'', b'', b'']
	# 		new_actor.relationships.y += 1
	# 		new_actor.relationships.section_3.append(self.actors.index(chest))
	# 		self.actors.append(new_actor)


	def setSmallKeyParams(self, model_path, model_name, room, key_index=0):
		keys = [a for a in self.actors if a.type == 0xA9]

		if len(keys) > key_index:
			key = keys[key_index]
			
			# key.type = 0x88 # GoldenLeaf
			key.parameters[1] = bytes(model_path, 'utf-8')
			key.parameters[2] = bytes(model_name, 'utf-8')
			key.parameters[3] = bytes(room, 'utf-8')
	

	def setRupeeParams(self, model_path, model_name, entry_point, rup_index=0):
		rups = [a for a in self.actors if a.type == 0xAB]

		if len(rups) > 0:
			rup = rups[0] # since we are changing the type, the list of rupees gets smaller, therefore we just get the first rup
			rup.type = 0x194 # sinking sword
			rup.parameters[0] = bytes(model_path, 'utf-8')
			rup.parameters[1] = bytes(model_name, 'utf-8')
			rup.parameters[2] = bytes(entry_point, 'utf-8')
			rup.parameters[3] = bytes('Lv10RupeeGet' if rup_index == 0 else f'Lv10RupeeGet_{rup_index + 1}', 'utf-8')
	

	def setLoadingZoneTarget(self, new_destination, index=0):
		zones = [a for a in self.actors if a.type == 0x190]

		if len(zones) > index:
			zone = zones[index]
			zone.parameters[0] = re.match(b'(.+)_\\d\\d[A-Z]', new_destination).group(1)
			zone.parameters[1] = new_destination
	

	def repack(self):
		new_names = b''

		for entry in self.fixed_hash.entries:
			if entry.name == b'actor':
				entry.data.entries = []
				for actor in self.actors:
					# Create a new entry for the actor in the actors FixedHash, using a newly packed data block for that actor
					entry.data.entries.append(Entry(0xFFF0, b'', 0xFFFFFFFF, actor.pack(len(new_names))))

					new_names += actor.name + b'\x00'

					for param in actor.parameters:
						if isinstance(param, bytes):
							new_names += param + b'\x00'

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
		
		if self.x > 0x00:
			for i in range(self.x):
				acts = []
				seq = []

				for b in range(2):
					param = readBytes(data, pos + (0x8 * b), 4)
					paramType = readBytes(data, pos + (0x8 * b) + 0x4, 4)
					if paramType == 0x4:
						seq.append(readString(names, param))
					else:
						seq.append(param)
				
				act_index = readBytes(data, pos + 0x10, 4)
				acts.append(seq)
				acts.append(act_index)
				self.section_1.append(acts)
				pos += 20
		
		if self.z > 0x00:
			for i in range(self.z):
				acts = []
				seq = []

				for b in range(2):
					param = readBytes(data, pos + (0x8 * b), 4)
					paramType = readBytes(data, pos + (0x8 * b) + 0x4, 4)
					if paramType == 0x4:
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
		
		if self.y > 0x00:
			for i in range(self.y):
				id = readBytes(data, pos + (0x4 * i), 4)
				self.section_3.append(id)
