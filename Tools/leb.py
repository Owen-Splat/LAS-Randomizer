import re

def readBytes(bytes, start, length, endianness='little'):
	return int.from_bytes(bytes[start : start + length], endianness)

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
		self.key = readBytes(data, 0x0, 8)
		self.name = readString(names, readBytes(data, 0x8, 4))

		if self.key != int(self.name[-16:], 16):
			raise ValueError(f'Actor key does not match for actor {hex(self.key)}')

		self.type = readBytes(data, 0xC, 2)
		self.xE = readBytes(data, 0xE, 2)
		self.roomID = readBytes(data, 0x10, 4)
		self.X = readBytes(data, 0x14, 4)
		self.Z = readBytes(data, 0x18, 4)
		self.Y = readBytes(data, 0x1C, 4)
		self.x20 = readBytes(data, 0x20, 8)
		self.x28 = readBytes(data, 0x28, 4)
		self.x2C = readBytes(data, 0x2C, 4)
		self.x30 = readBytes(data, 0x30, 4)
		self.x34 = readBytes(data, 0x34, 4)

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

		self.x84 = data[0x84:]

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
		packed += self.X.to_bytes(4, 'little')
		packed += self.Z.to_bytes(4, 'little')
		packed += self.Y.to_bytes(4, 'little')
		packed += self.x20.to_bytes(8, 'little')
		packed += self.x28.to_bytes(4, 'little')
		packed += self.x2C.to_bytes(4, 'little')
		packed += self.x30.to_bytes(4, 'little')
		packed += self.x34.to_bytes(4, 'little')

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

		packed += self.x84

		return packed



	def display(self):
		print(f'Name: {self.name}')
		print(f'Type: {self.type}')
		print(f'Room ID: {self.roomID}')
		print(f'Coordinates: {self.X}, {self.Y}, {self.Z}')
		print(f'Parameters: {self.parameters}')


class Room:
	def __init__(self, data):
		self.fixedHash = FixedHash(data)

		self.actors = []
		actorEntry = list(filter(lambda e: e.name == b'actor', self.fixedHash.entries))[0]

		for entry in actorEntry.data.entries:
			self.actors.append(Actor(entry.data, self.fixedHash.namesSection))


	def setChestContent(self, newContent, room, chestIndex=0):
		chests = list(filter(lambda a: a.type == 0xF7, self.actors))

		if len(chests) > chestIndex:
			chest = chests[chestIndex]

			if newContent == '$ENEMY' or room == 'taltal-5-chest-puzzle':
				chest.parameters[1] = bytes(newContent, 'utf-8')
			else:
				chest.parameters[1] = bytes(f'$EXT:{room}', 'utf-8')
			
			chest.parameters[2] = b''
	

	def setSmallKeyParams(self, modelPath, modelName, entryPoint, keyIndex=0):
		keys = list(filter(lambda a: a.type == 0xA9, self.actors))

		if len(keys) > keyIndex:
			key = keys[keyIndex]
			key.parameters[1] = bytes(modelPath, 'utf-8')
			key.parameters[2] = bytes(modelName, 'utf-8')
			key.parameters[3] = bytes(entryPoint, 'utf-8')
	

	def setLoadingZoneTarget(self, newDestination, index=0):
		zones = list(filter(lambda a: a.type == 0x190, self.actors))

		if len(zones) > index:
			zone = zones[index]
			zone.parameters[0] = re.match(b'(.+)_\\d\\d[A-Z]', newDestination).group(1)
			zone.parameters[1] = newDestination
	

	def repack(self):
		newNames = b''

		for entry in self.fixedHash.entries:
			if entry.name == b'actor':
				entry.data.entries = []
				for actor in self.actors:
					# Create a new entry for the actor in the actors FixedHash, using a newly packed data block for that actor
					entry.data.entries.append(Entry(0xFFF0, b'', 0xFFFFFFFF, actor.pack(len(newNames))))

					newNames += actor.name + b'\x00'

					for param in actor.parameters:
						if isinstance(param, bytes):
							newNames += param + b'\x00'

			newNames += entry.name + b'\x00'

		self.fixedHash.namesSection = newNames

		return self.fixedHash.toBinary()
