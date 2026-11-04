"""Build standalone indexed-source hooks from a user's clean LAS 1.0.0 main."""
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from .nso import NSO, align, gate, branch, make_elf_nso
MAIN_SHA256 = '20965546519a8e08cc01e6f138982390546d56520703684967425b09230e9b6d'
ADD, HAS = (9242848, 9247280)
WORLD_NPC = 9191184
WORLD_PROLOGUE = bytes.fromhex('ff0301d1ffd700a9f44f02a9fd7b03a9')
PROLOGUES = {ADD: bytes.fromhex('ff4301d1f70b00f9f65702a9f44f03a9'), HAS: bytes.fromhex('ffc300d1f44f01a9fd7b02a9fd830091')}

def validate_input(romfs_folder):
    main_path = Path(romfs_folder).resolve().parent / 'exefs/main'
    if not main_path.is_file() or hashlib.sha256(main_path.read_bytes()).hexdigest() != MAIN_SHA256:
        raise ValueError('Randomized shell pickups and shop require clean LAS 1.0.0 ExeFS alongside RomFS (exefs/main).')
    return main_path

def build(main_path, output_folder, source_rows, build_folder):
    source_rows = list(source_rows)
    if not source_rows:
        return
    if len({(source_row['item'], source_row['index']) for source_row in source_rows}) != len(source_rows):
        raise ValueError('Duplicate indexed source')
    # Each source and pending shop reward needs its own save flag.
    allocated_flags = []
    for source_row in source_rows:
        if not 1248 <= source_row['flag'] < 2048 or not (source_row['pending'] == -1 or 1248 <= source_row['pending'] < 2048):
            raise ValueError('Invalid source flag')
        if not (source_row['item'] == 22 and 0 <= source_row['index'] < 50 or (source_row['item'] == 58 and 0 <= source_row['index'] < 32) or (230 <= source_row['item'] < 240 and source_row['index'] == -1)):
            raise ValueError('Unsupported source identity')
        allocated_flags.append(source_row['flag'])
        if source_row['pending'] >= 0:
            allocated_flags.append(source_row['pending'])
    if len(set(allocated_flags)) != len(allocated_flags):
        raise ValueError('Duplicate source flag')
    # Patch only the clean, supported executable.
    main_bytes = Path(main_path).read_bytes()
    if hashlib.sha256(main_bytes).hexdigest() != MAIN_SHA256:
        raise ValueError('Unsupported or modified LAS executable')
    game_executable = NSO(main_bytes)
    shell_visuals = [source_row for source_row in source_rows if source_row.get('world_npc')]
    if any((source_row['item'] != 22 or source_row['world_npc'] != f'LAS_WorldShell_{source_row['index']}' for source_row in shell_visuals)):
        raise ValueError('Invalid shell visual identity')
    # Check that every selected shell visual exists in the generated NPC sheet.
    if shell_visuals:
        from RandomizerCore.Tools import oead_tools as sheet_tools
        npc_sheet = sheet_tools.readSheet(Path(output_folder).parent / 'romfs/region_common/datasheets/Npc.gsheet')
        for row in shell_visuals:
            matching_definitions = [source_row for source_row in npc_sheet['values'] if source_row['symbol'] == row['world_npc']]
            if len(matching_definitions) != 1 or matching_definitions[0]['graphics']['path'] != row['model_path'] or matching_definitions[0]['graphics']['model'] != row['model_name']:
                raise ValueError('Shell NPC visual definition mismatch')
        if game_executable.read(WORLD_NPC, 16) != WORLD_PROLOGUE:
            raise ValueError('Unexpected NPC visual constructor')
    for offset, expected_instructions in PROLOGUES.items():
        if game_executable.read(offset, 16) != expected_instructions:
            raise ValueError('Unexpected hook instructions')
    # Reserve space for the hook addresses written when the module starts.
    hook_mailbox_offset = align(game_executable.segments[2][0] + len(game_executable.segments[2][1]) + game_executable.bss)
    game_executable.bss = hook_mailbox_offset + 4096 - game_executable.segments[2][0] - len(game_executable.segments[2][1])
    module_header_offset = struct.unpack('<I', game_executable.read(4, 4))[0]
    game_executable.write(module_header_offset + 12, struct.pack('<I', hook_mailbox_offset + 4096 - module_header_offset))
    # Place small branches after the original executable code.
    hook_code_offset = align(len(game_executable.segments[0][1]), 16)
    hook_code = bytearray(hook_code_offset - len(game_executable.segments[0][1]))
    hook_branches = {}
    for hook_index, hook_address in enumerate((ADD, HAS) + ((WORLD_NPC,) if shell_visuals else ())):
        branch_target = hook_code_offset + hook_index * 36
        hook_code.extend(gate(branch_target, hook_mailbox_offset + hook_index * 8, hook_address + 16, WORLD_PROLOGUE if hook_address == WORLD_NPC else PROLOGUES[hook_address]))
        hook_branches[hook_address] = struct.pack('<4I', branch(hook_address, branch_target), 3573751839, 3573751839, 3573751839)
        game_executable.write(hook_address, hook_branches[hook_address])
    if len(game_executable.segments[0][1]) + len(hook_code) > game_executable.segments[1][0]:
        raise ValueError('No text gate space')
    game_executable.segments[0][1].extend(hook_code)

    def format_byte_array(array_name, byte_values):
        return 'static const unsigned char ' + array_name + '[]={' + ','.join(map(str, byte_values)) + '};\n'
    # Give the native runtime the source table and verified hook locations.
    profile_header = f'#define TEXT_SIZE {len(game_executable.segments[0][1])}ull\n#define MAILBOX {hook_mailbox_offset}ull\n#define ADD_OFFSET {ADD}ull\n#define HAS_OFFSET {HAS}ull\n'
    profile_header += format_byte_array('MAIN_SIGNATURE', game_executable.read(0, 32)) + format_byte_array('ADD_GATE', hook_branches[ADD]) + format_byte_array('HAS_GATE', hook_branches[HAS])
    profile_header += f'#define WORLD_VISUAL_COUNT {len(shell_visuals)}u\n#define WORLD_NPC_OFFSET {WORLD_NPC}ull\n'
    if shell_visuals:
        profile_header += format_byte_array('WORLD_NPC_GATE', hook_branches[WORLD_NPC])
    profile_header += 'typedef struct {const char *text;unsigned long long length;} VisualName;\n'
    profile_header += 'typedef struct {unsigned item,index;VisualName name;} WorldVisual;\n'
    profile_header += 'static const WorldVisual WORLD_VISUALS[]={' + ','.join(('{' + f'{source_row['item']},{source_row['index']},' + '{' + json.dumps(source_row['world_npc']) + ',' + str(len(source_row['world_npc'])) + '}}' for source_row in shell_visuals)) + '};\n'
    profile_header += 'typedef struct {unsigned item;int index;unsigned flag;int pending;} Source;\n'
    profile_header += f'#define SOURCE_COUNT {len(source_rows)}u\nstatic const Source SOURCES[]={{'
    profile_header += ','.join(('{' + ','.join((str(source_row[field_name]) for field_name in ('item', 'index', 'flag', 'pending'))) + '}' for source_row in source_rows)) + '};\n'
    build_folder = Path(build_folder)
    build_folder.mkdir(parents=True, exist_ok=True)
    (build_folder / 'profile.h').write_text(profile_header)
    native_source_folder = Path(__file__).parent
    if getattr(sys, 'frozen', False):
        native_source_folder = Path(sys.executable).parent / 'NativeSources'
    import ziglang
    compiler_path = Path(ziglang.__file__).parent / ('zig.exe' if os.name == 'nt' else 'zig')
    compiler_environment = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(build_folder / 'zig-cache'))
    module_elf_path = build_folder / 'standalone.elf'
    # Compile the runtime locally; no game binaries are shipped with the source.
    subprocess.run([str(compiler_path), 'cc', '-target', 'aarch64-linux-musl', '-O2', '-fPIC', '-ffreestanding', '-fno-stack-protector', '-fno-builtin', '-nostdlib', '-shared', '-Wl,-Bsymbolic,--hash-style=sysv,--build-id=sha1', '-Wl,-T,' + str(native_source_folder / 'link.ld'), '-I' + str(build_folder), str(native_source_folder / 'runtime.c'), str(native_source_folder / 'entry.S'), '-o', str(module_elf_path)], env=compiler_environment, check=True)
    # Check both output executables before writing them.
    module_bytes = make_elf_nso(module_elf_path)
    patched_main_bytes = game_executable.encode()
    NSO(module_bytes)
    NSO(patched_main_bytes)
    output_folder = Path(output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)
    if (output_folder / 'subsdk9').exists():
        raise ValueError('Refusing to overwrite an existing subsdk9')
    (output_folder / 'main').write_bytes(patched_main_bytes)
    (output_folder / 'subsdk9').write_bytes(module_bytes)
    (build_folder / 'sources.json').write_text(json.dumps(source_rows, indent=2))
