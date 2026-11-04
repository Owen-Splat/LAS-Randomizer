from RandomizerCore.Tools.fixed_hash import *
import struct



class Level:
	def __init__(self, data):
		self.fixed_hash = FixedHash(data)
		
		# self.nodes = []
		# node_entry = [e for e in self.fixed_hash.entries if e.name == b'node'][0]
		# for entry in node_entry.data.entries:
		# 	self.nodes.append(Node(entry.data))

		self.zones = []
		zone_entry = [e for e in self.fixed_hash.entries if e.name == b'zone'][0]
		for entry in zone_entry.data.entries:
			self.zones.append(Zone(entry.data))

		# self.player_starts = []
		# start_entry = [e for e in self.fixed_hash.entries if e.name == b'tagPlayerStart'][0]
		# for entry in start_entry.data.entries:
		# 	self.player_starts.append(tagPlayerStart(entry.name, entry.data))

		config_entry = [e for e in self.fixed_hash.entries if e.name == b'config'][0]
		self.config = Config(config_entry.data)
	
	
	def repack(self):
		# new_names = b''
		
		for entry in self.fixed_hash.entries:
			if entry.name == b'zone':
				entry.data.entries = []
				for zone in self.zones:
					entry.data.entries.append(Entry(0xFFF0, b'', 0xFFFFFFFF, zone.pack()))

			# if entry.name == b'tagPlayerStart':
			# 	entry.data.entries = []
			# 	for start in self.player_starts:
			# 		entry.data.entries.append(Entry(0xFFF0, start.name, 0xFFFFFFFF, start.pack()))
			
			if entry.name == b'config':
				entry.data = self.config.pack()
			
			# new_names += entry.name + b'\x00'
		
		# self.fixed_hash.namesSection = new_names
		
		return self.fixed_hash.toBinary()



# This is a FixedHash child. Seems to contain an entry for each room? Each entry holds 32 bytes of data
# Not yet understood
class Node:
	def __init__(self, data):
		pass


	def repack(self):
		pass



# This is a FixedHash child. Each entry holds 64 bytes of data
# Not yet understood
class Area:
	def __init__(self, data):
		pass


	def repack(self):
		pass



# This is a FixedHash child. It contains an entry for each room where a room is defined by the camera bounds
# Field is an exception, where it seems to define regions instead
# This likely defines some properties for each room
# This defines the room ID, BGM, ambience, and even some sort of room type
# Not fully understood
class Zone:
	def __init__(self, data):
		self.room_ID = readBytes(data, 0x0, 4)
		self.unknown_1 = data[0x4:0x3C]
		self.bgm = readString(data, 0x3C, as_string=True)
		self.se_amb = readString(data, 0x5C, as_string=True)
		self.group_amb = readString(data, 0x7C, as_string=True)
		self.unknown_2 = data[0x9C:0xB0]
		self.room_type = readString(data, 0xB0, as_string=True)
	

	def pack(self):
		packed = b''
		packed += self.room_ID.to_bytes(4, 'little')
		packed += self.unknown_1
		packed += bytes(self.bgm, 'utf-8')

		padding = b''
		for i in range(32-len(self.bgm)):
			padding += b'\x00'
		
		packed += padding
		packed += bytes(self.se_amb, 'utf-8')

		padding = b''
		for i in range(32-len(self.se_amb)):
			padding += b'\x00'
		
		packed += padding
		packed += bytes(self.group_amb, 'utf-8')

		padding = b''
		for i in range(32-len(self.group_amb)):
			padding += b'\x00'
		
		packed += padding
		packed += self.unknown_2
		packed += bytes(self.room_type, 'utf-8')

		padding = b''
		for i in range(32-len(self.room_type)):
			padding += b'\x00'
		
		packed += padding
		
		return packed



# This is a FixedHash child
# There is an entry for every tagPlayerStart actor, with the entry name matching the first actor parameter
# Each entry holds 16 bytes of data, the first 12 being 3 floats, which are the coordinate points of each actor
# Last 4 bytes are not yet understood, although they appear to be Y-rotation / 45.0
# For the rotations that aren't divided evenly, there's a decent margin of error
class tagPlayerStart:
	def __init__(self, name, data):
		self.name = name
		self.pos_x = readFloat(data, 0x0, 4)
		self.pos_y = readFloat(data, 0x4, 4)
		self.pos_z = readFloat(data, 0x8, 4)
		self.unknown = data[0xC:0x10]


	def pack(self):
		packed = b''
		packed += struct.pack('<f', self.pos_x)
		packed += struct.pack('<f', self.pos_y)
		packed += struct.pack('<f', self.pos_z)
		packed += self.unknown

		return packed



# This is a FixedHash child
# Each entry holds 48 bytes of data
# Not yet understood
class staticObject:
	def __init__(self, data):
		pass


	def repack(self):
		pass



# Only Field has this entry
# Holds 16 bytes of data
# Not yet understood
class gridConfig:
	def __init__(self, data):
		pass


	def repack(self):
		pass



# Only Field has this entry
# Holds 163840 bytes of data
# Not yet understood
class grid:
	def __init__(self, data):
		pass


	def repack(self):
		pass



# Only Field actually has any data, and contains BowWowKidnap twice, perhaps doing 2 different things for if it's true and false?
# Not yet understood
class Condition:
	def __init__(self, data):
		pass


	def repack(self):
		pass



# Holds 7 bytes of data that define properties of the level. The last 5 bytes always seem to be x00\x00\x00\x00\xff, maybe padding?
# Only the first 2 bytes ever change. The second byte determines if companions will load
# The first byte is not yet understood
class Config:
	def __init__(self, data):
		self.attr_1 = readBytes(data, 0x0, 1)
		self.allow_companions = bool(readBytes(data, 0x1, 1))
		self.attr_3 = readBytes(data, 0x2, 1)
		self.attr_4 = readBytes(data, 0x3, 1)
		self.attr_5 = readBytes(data, 0x4, 1)
		self.attr_6 = readBytes(data, 0x5, 1)
		self.padding = b'\xFF'
	
	
	def pack(self):
		packed = b''
		packed += self.attr_1.to_bytes(1, 'little')
		packed += self.allow_companions.to_bytes(1, 'little')
		packed += self.attr_3.to_bytes(1, 'little')
		packed += self.attr_4.to_bytes(1, 'little')
		packed += self.attr_5.to_bytes(1, 'little')
		packed += self.attr_6.to_bytes(1, 'little')
		packed += self.padding
		
		return packed



# Holds 3 bytes of data, which seem to always be 0x100182
# Given the name, this is probably just a version marker and has no functional purpose
class Version:
	def __init__(self, data):
		pass


	def repack(self):
		pass
