from RandomizerCore.Tools.fixed_hash import *
import struct, enum


class Kodama:
	"""Handles environment effects. It is a FixedHash file format
	
	Every entry has 300 bytes of data. The data is not fully understood"""

	def __init__(self, data) -> None:
		self.fixed_hash = FixedHash(data)
		self.environments: dict[str, Environment] = {}
		for entry in self.fixed_hash.entries:
			print(entry.data)
			self.environments[str(entry.name, 'utf-8')] = Environment(entry.data)
		self.fixed_hash.entries.clear() # no reason to keep it in memory when we don't need it anymore
		for k,env in self.environments.items():
			# if env.effect_preset in (Environment.Effect.HEAT_SIDESCROLLER.value, Environment.Effect.SIDESCROLLER.value):
			print(k, env.effect_preset)


	def repack(self) -> bytes:
		for k, env in self.environments.items():
			self.fixed_hash.entries.append(Entry(0xFFF0, bytes(k, 'utf-8'), 0xFFFFFFFF, env.pack()))

		return self.fixed_hash.toBinary()


class Environment:
	class Effect(enum.IntEnum):
		CLEAR				= 0
		FOG					= 1
		SAND				= 2
		HEAT				= 3
		HEAT_SIDESCROLLER	= 4
		BLUE_PARTICLES		= 5
		DARK				= 6
		LESS_DARK			= 7
		INSIDE				= 8
		SIDESCROLLER		= 9


	def __init__(self, data: bytes) -> None:
		# first 12 bytes seems to be some sort of info
		# 8 bytes that I haven't made any sense of, then 4 null bytes of padding
		# for now we just parse the info we actually do understand
		self.unk1 = data[0:56]
		self.light_color = Color(data[56], data[57], data[58], data[59])
		self.light_direction = readFloat(data, 60, 4)
		self.light_unk = readBytes(data, 64, 4)
		self.light_intensity = readFloat(data, 68, 4)
		self.unk2 = data[72:116]
		# I should make a Vector3 class and use it for both this and leb actors (pos, rot, scale)
		self.wind_direction_x = readFloat(data, 116, 4)
		self.wind_direction_y = readFloat(data, 120, 4)
		self.wind_direction_z = readFloat(data, 124, 4)
		self.unk3 = data[128:296]
		self.effect_preset = Environment.Effect(data[296])


	def pack(self) -> bytes:
		packed = b''
		packed += self.unk1
		packed += self.light_color.pack()
		packed += struct.pack('<f', self.light_direction)
		packed += self.light_unk.to_bytes(4, 'little')
		packed += struct.pack('<f', self.light_intensity)
		packed += self.unk2
		packed += struct.pack('<f', self.wind_direction_x)
		packed += struct.pack('<f', self.wind_direction_y)
		packed += struct.pack('<f', self.wind_direction_z)
		packed += self.unk3
		packed += self.effect_preset.to_bytes(1, 'little')
		packed += b'Shu' # some weird padding, it is done in a couple places in the env data
		return packed


class Color:
	def __init__(self, r: int, g: int, b: int, a: int) -> None:
		self.r = r
		self.g = g
		self.b = b
		self.a = a


	def pack(self) -> bytes:
		packed = b''
		packed += self.r.to_bytes(1, 'little')
		packed += self.g.to_bytes(1, 'little')
		packed += self.b.to_bytes(1, 'little')
		packed += self.a.to_bytes(1, 'little')
		return packed
