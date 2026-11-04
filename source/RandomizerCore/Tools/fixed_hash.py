import struct

def readBytes(bytes, start, length, endianness='little'):
	return int.from_bytes(bytes[start : start + length], endianness)


def readFloat(bytes, start, length):
	return float(struct.unpack('<f', bytes[start : start + length])[0])


def readString(data, start, as_string=False):
	result = b''
	index = start

	while index < len(data) and data[index]:
		result += data[index : index + 1]
		index += 1
	
	if as_string:
		result = str(result, 'utf-8')
	
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
				#pass
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

		while (len(result) + offset) % 8 != 0:
			result += b'\x00'
		result += entriesSect

		while (len(result) + offset) % 8 != 0:
			result += b'\x00'
		result += entryOffsetsSect

		while (len(result) + offset) % 8 != 0:
			result += b'\x00'
		result += dataSect

		while (len(result) + offset) % 4 != 0:
			result += b'\x00'
		result += len(self.namesSection).to_bytes(4, 'little')
		result += self.namesSection

		return result
