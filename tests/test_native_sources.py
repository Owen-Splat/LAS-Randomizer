"""Execute standalone ARM64 source hooks. Set LAS_TEST_MOD to private generated output.

Game assets and generated binaries must not be committed to the repository.
Requires unicorn==2.1.4 in addition to the builder dependencies.
"""
import json
import os
from pathlib import Path
import struct
import sys
import unittest
from elftools.elf.elffile import ELFFile
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))
from RandomizerCore.Native.nso import NSO, align
try:
    from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_INTR
    from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_SP, UC_ARM64_REG_PC
except ImportError:
    Uc = None
GAME_BASE_ADDRESS = 485331304448
MODULE_BASE_ADDRESS = 489626271744
STACK_ADDRESS = 493921239040
RETURN_ADDRESS = 498216206336
GENERATED_MOD_PATH = os.environ.get('LAS_TEST_NATIVE_MOD', os.environ.get('LAS_TEST_MOD'))

@unittest.skipUnless(GENERATED_MOD_PATH and Uc, 'Set LAS_TEST_MOD and install Unicorn to execute private-asset native tests')
class NativeSources(unittest.TestCase):

    def setUp(self):
        mod_folder = Path(GENERATED_MOD_PATH)
        self.source_rows = json.loads((mod_folder / 'native-build/sources.json').read_text())
        self.game_executable = NSO((mod_folder / 'exefs/main').read_bytes())
        self.native_module = NSO((mod_folder / 'exefs/subsdk9').read_bytes())
        self.emulator = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        for load_address, executable in ((GAME_BASE_ADDRESS, self.game_executable), (MODULE_BASE_ADDRESS, self.native_module)):
            self.emulator.mem_map(load_address, align(executable.segments[2][0] + len(executable.segments[2][1]) + executable.bss))
            for segment_offset, segment_bytes in executable.segments:
                self.emulator.mem_write(load_address + segment_offset, bytes(segment_bytes))
        self.emulator.mem_map(STACK_ADDRESS, 131072)
        self.emulator.mem_map(RETURN_ADDRESS, 4096)
        with (mod_folder / 'native-build/standalone.elf').open('rb') as stream:
            module_elf = ELFFile(stream)
            self.symbols = {symbol.name: MODULE_BASE_ADDRESS + symbol['st_value'] for symbol in module_elf.get_section_by_name('.symtab').iter_symbols()}
            for section in module_elf.iter_sections():
                if section['sh_type'] == 'SHT_RELA':
                    for relocation in section.iter_relocations():
                        self.assertEqual(relocation['r_info_type'], 1027)
                        self.emulator.mem_write(MODULE_BASE_ADDRESS + relocation['r_offset'], struct.pack('<Q', MODULE_BASE_ADDRESS + relocation['r_addend']))
            self.assertIn('DT_INIT', [dynamic_tag.entry.d_tag for dynamic_tag in module_elf.get_section_by_name('.dynamic').iter_tags()])
        # Stand in for the original game functions and record their arguments.
        self.forwarded_calls = []
        self.emulator.hook_add(UC_HOOK_INTR, self.interrupt)
        self.emulator.hook_add(UC_HOOK_CODE, self.instruction)
        self.call(self.symbols['_init'])
        self.assertEqual(self.read_uint64(self.symbols['main_base']), GAME_BASE_ADDRESS)
        self.emulator.mem_write(self.symbols['original_add_tail'], struct.pack('<Q', RETURN_ADDRESS + 256))
        self.emulator.mem_write(self.symbols['original_has_tail'], struct.pack('<Q', RETURN_ADDRESS + 260))
        self.emulator.mem_write(self.symbols['original_world_npc_tail'], struct.pack('<Q', RETURN_ADDRESS + 264))
        self.emulator.mem_write(GAME_BASE_ADDRESS + 30151560, struct.pack('<Q', GAME_BASE_ADDRESS + 30126624 + 24000))
        self.emulator.mem_write(GAME_BASE_ADDRESS + 30151568, struct.pack('<Q', 256))

    def read_uint64(self, address):
        return struct.unpack('<Q', self.emulator.mem_read(address, 8))[0]

    def interrupt(self, emulator, number, user_data):
        program_counter = emulator.reg_read(UC_ARM64_REG_PC)
        instruction = struct.unpack('<I', emulator.mem_read(program_counter - 4, 4))[0]
        self.assertEqual(instruction >> 5 & 65535, 6)
        requested_address = emulator.reg_read(UC_ARM64_REG_X2)
        text_end_address = GAME_BASE_ADDRESS + align(len(self.game_executable.segments[0][1]))
        if requested_address < GAME_BASE_ADDRESS:
            memory_info = (0, GAME_BASE_ADDRESS, 0, 0, 0, 0, 0, 0)
        elif requested_address < text_end_address:
            memory_info = (GAME_BASE_ADDRESS, text_end_address - GAME_BASE_ADDRESS, 3, 0, 5, 0, 0, 0)
        else:
            emulator.reg_write(UC_ARM64_REG_X0, 1)
            return
        emulator.mem_write(emulator.reg_read(UC_ARM64_REG_X0), struct.pack('<QQ6I', *memory_info))
        emulator.reg_write(UC_ARM64_REG_X0, 0)
        for register_index in range(3, 18):
            emulator.reg_write(UC_ARM64_REG_X0 + register_index, 12242944 + register_index)

    def instruction(self, emulator, address, size, user_data):
        if address == RETURN_ADDRESS:
            emulator.emu_stop()
            return
        if address in (RETURN_ADDRESS + 256, RETURN_ADDRESS + 260, RETURN_ADDRESS + 264):
            arguments = [emulator.reg_read(UC_ARM64_REG_X0 + register_index) for register_index in range(8)]
            self.forwarded_calls.append((address, arguments))
            emulator.reg_write(UC_ARM64_REG_SP, emulator.reg_read(UC_ARM64_REG_SP) + {RETURN_ADDRESS + 256: 80, RETURN_ADDRESS + 260: 48, RETURN_ADDRESS + 264: 64}[address])
            emulator.reg_write(UC_ARM64_REG_X0, 77)
            emulator.reg_write(UC_ARM64_REG_PC, emulator.reg_read(UC_ARM64_REG_X30))

    def call(self, address, arguments=()):
        self.emulator.reg_write(UC_ARM64_REG_SP, STACK_ADDRESS + 126976)
        for register_index in range(29):
            self.emulator.reg_write(UC_ARM64_REG_X0 + register_index, 0)
        for register_index, value in enumerate(arguments):
            self.emulator.reg_write(UC_ARM64_REG_X0 + register_index, value & 18446744073709551615)
        self.emulator.reg_write(UC_ARM64_REG_X30, RETURN_ADDRESS)
        self.emulator.emu_start(address, RETURN_ADDRESS + 4, count=1000000)
        self.assertEqual(self.emulator.reg_read(UC_ARM64_REG_PC), RETURN_ADDRESS)
        self.assertEqual(self.emulator.reg_read(UC_ARM64_REG_SP), STACK_ADDRESS + 126976)
        return self.emulator.reg_read(UC_ARM64_REG_X0)

    def set_flag(self, flag_index, value):
        address = GAME_BASE_ADDRESS + 30126624 + 24000 + flag_index // 8
        flag_byte = self.emulator.mem_read(address, 1)[0]
        self.emulator.mem_write(address, bytes([flag_byte | 1 << flag_index % 8 if value else flag_byte & ~(1 << flag_index % 8)]))

    def test_indexed_sources_suppress_vanilla_grant_and_use_saved_source_ownership(self):
        indexed_sources = [relocation for relocation in self.source_rows if relocation['index'] >= 0]
        self.assertEqual(len(indexed_sources), 38)
        for row in indexed_sources:
            self.assertEqual(self.call(GAME_BASE_ADDRESS + 9247280, [row['item'], 1, row['index']]), 0)
            self.call(GAME_BASE_ADDRESS + 9242848, [row['item'], 1, row['index']])
            self.assertEqual(self.forwarded_calls, [])
            self.set_flag(row['flag'], True)
            self.assertEqual(self.call(GAME_BASE_ADDRESS + 9247280, [row['item'], 1, row['index']]), 1)
            self.set_flag(row['flag'], False)
            self.assertEqual(self.call(GAME_BASE_ADDRESS + 9247280, [row['item'], 1, row['index']]), 0)

    def test_real_collectibles_bypass_source_interception_and_decode_index(self):
        for item_id, collectible_count in ((22, 50), (58, 32)):
            for index in range(collectible_count):
                arguments = [item_id, 1, 1397161984 | index, 3, 4, 5, 6, 7]
                self.assertEqual(self.call(GAME_BASE_ADDRESS + 9242848, arguments), 77)
                arguments[2] = index
                self.assertEqual(self.forwarded_calls[-1], (RETURN_ADDRESS + 256, arguments))
            previous_state = len(self.forwarded_calls)
            self.call(GAME_BASE_ADDRESS + 9242848, [item_id, 1, 1397161984 | collectible_count])
            self.assertEqual(len(self.forwarded_calls), previous_state)

    def test_stolen_shop_dummies_queue_without_entering_inventory(self):
        source_rows = [relocation for relocation in self.source_rows if relocation['pending'] >= 0]
        if not source_rows:
            self.skipTest('Shop patch is not installed')
        self.assertEqual(len(source_rows), 10)
        for row in source_rows:
            self.call(GAME_BASE_ADDRESS + 9242848, [row['item'], 1, -1])
            self.assertEqual(self.forwarded_calls, [])
            address = GAME_BASE_ADDRESS + 30126624 + 24000 + row['pending'] // 8
            self.assertTrue(self.emulator.mem_read(address, 1)[0] & 1 << row['pending'] % 8)
            self.assertEqual(self.call(GAME_BASE_ADDRESS + 9247280, [row['item'], 1, -1]), 0)
            self.set_flag(row['flag'], True)
            self.assertEqual(self.call(GAME_BASE_ADDRESS + 9247280, [row['item'], 1, -1]), 1)

    def test_aggregate_and_unrelated_inventory_calls_are_forwarded(self):
        for arguments in ([22, 50, -1, 3, 4, 5, 6, 7], [6, 1, -1, 3, 4, 5, 6, 7], [22, 1, 49, 3, 4, 5, 6, 7]):
            if any((relocation['item'] == arguments[0] and relocation['index'] == arguments[2] for relocation in self.source_rows)):
                continue
            self.assertEqual(self.call(GAME_BASE_ADDRESS + 9247280, arguments), 77)
            self.assertEqual(self.forwarded_calls[-1][1], [argument & 18446744073709551615 for argument in arguments])
        self.assertEqual(self.call(GAME_BASE_ADDRESS + 9242848, [105, 1, -1, 3, 4, 5, 6, 7]), 77)

    def test_shop_dummies_never_reach_inventory_when_save_pointer_is_unavailable(self):
        self.emulator.mem_write(GAME_BASE_ADDRESS + 30151560, struct.pack('<Q', 0))
        for row in self.source_rows:
            if row['pending'] >= 0:
                self.assertEqual(self.call(GAME_BASE_ADDRESS + 9242848, [row['item'], 1, -1]), 0)
        self.assertEqual(self.forwarded_calls, [])

    def test_world_visuals_preserve_actors_and_forward_constructor_arguments(self):
        source_rows = [relocation for relocation in self.source_rows if relocation.get('world_npc')]
        self.assertEqual(len(source_rows), 33)
        # Build the same actor and context layout used by the game.
        actor_address, context_address, name_span_address, name_text_address = (STACK_ADDRESS + 4096, STACK_ADDRESS + 8192, STACK_ADDRESS + 8448, STACK_ADDRESS + 8704)
        self.emulator.mem_write(context_address + 24, struct.pack('<QQ', actor_address, 305419896))
        self.emulator.mem_write(name_text_address, b'ItemSecretSeashell')
        self.emulator.mem_write(name_span_address, struct.pack('<QQ', name_text_address, 18))
        for row in source_rows:
            self.emulator.mem_write(actor_address, bytes(768))
            self.emulator.mem_write(actor_address, struct.pack('<Q', GAME_BASE_ADDRESS + 29135880))
            self.emulator.mem_write(actor_address + 160, struct.pack('<H', 135))
            self.emulator.mem_write(actor_address + 188, struct.pack('<II', row['index'], 3))
            self.emulator.mem_write(actor_address + 744, b'\x16')
            previous_state = bytes(self.emulator.mem_read(actor_address, 768))
            arguments = [123, context_address, name_span_address, 3, 4, 5, 6, 7]
            self.assertEqual(self.call(GAME_BASE_ADDRESS + 9191184, arguments), 77)
            forwarded_arguments = self.forwarded_calls[-1][1]
            text_address, text_length = struct.unpack('<QQ', self.emulator.mem_read(forwarded_arguments[2], 16))
            self.assertEqual(bytes(self.emulator.mem_read(text_address, text_length)).decode(), row['world_npc'])
            self.assertEqual(forwarded_arguments[:2] + forwarded_arguments[3:], arguments[:2] + arguments[3:])
            self.assertEqual(bytes(self.emulator.mem_read(actor_address, 768)), previous_state)
            self.assertEqual(self.read_uint64(context_address + 32), 305419896)
            # Unrelated actors must keep their original visual name.
            for offset, value in ((0, b'\x00' * 8), (160, b'\x00\x00'), (744, b':'), (192, b'\x00' * 4), (188, struct.pack('<I', 999))):
                original_bytes = bytes(self.emulator.mem_read(actor_address + offset, len(value)))
                self.emulator.mem_write(actor_address + offset, value)
                self.assertEqual(self.call(GAME_BASE_ADDRESS + 9191184, arguments), 77)
                self.assertEqual(self.forwarded_calls[-1][1], arguments)
                self.emulator.mem_write(actor_address + offset, original_bytes)
if __name__ == '__main__':
    unittest.main()
