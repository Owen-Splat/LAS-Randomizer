from RandomizerCore.Tools.exefs_editor.patcher import Patcher
from RandomizerCore.Paths.randomizer_paths import ASM_PATH, IS_RUNNING_FROM_SOURCE
import os, random


def createRandomizerPatches(rand_state: tuple, settings: dict):
    asm_data = preSetup(rand_state, settings)
    patcher = Patcher()

    asm_files = [f for f in os.listdir(ASM_PATH) if f.endswith('.asm')]
    for asm in asm_files:
        patches = readASM(asm, asm_data, settings)
        for patch in patches:
            address, instruction, comment = patch
            if instruction.startswith('.string'):
                instruction = instruction.split('.string ')[1]
                instruction = instruction.split('; ')[0]
                patcher.replaceString(address, instruction, comment)
            elif instruction.startswith('.short'):
                instruction = instruction.split('.short ')[1]
                instruction = instruction.split('; ')[0]
                instruction = instruction.replace('#', '')
                patcher.replaceShort(address, int(instruction), comment)
            else:
                patcher.addPatch(address, instruction, comment)

    return patcher


def readASM(asm, asm_data, settings):
    with open(f'{ASM_PATH}/{asm}', 'r') as f:
        asm_lines = f.read().splitlines()

    patches = []
    offset = 0
    instruction = ''
    patch_info = ''
    condition_met = True

    for line in asm_lines:
        line = line.strip()

        # store pchtxt patch titles, skip over comments
        if line.startswith(';*'):
            if len(patch_info) > 0:
                patch_info += '\n'
            patch_info += line.replace(';*', '//')
            continue
        elif line.startswith('; '):
            continue

        # parse condition
        if line.startswith(';settings'):
            condition = line.split(' ')[1]
            state = True
            if condition.startswith('!'):
                state = False
                condition = condition.split('!')[1]
            if condition not in settings:
                condition_met = False
            else:
                condition_met = True if settings[condition] == state else False
            continue

        # add the patch if the line is blank, reset data and skip
        # reset condition & comment block, skip
        if len(line) == 0:
            if offset > 0 and len(instruction) > 0 and condition_met:
                patches.append((offset, instruction, patch_info))
            condition_met = True
            instruction = ''
            patch_info = ''
            offset = 0
            continue

        # skip lines if the condition is not met (until blank line which resets the condition)
        if not condition_met:
            continue

        # replace data in line
        if ';data' in line:
            line_data = line.split(';data ')
            needed_data = asm_data[line_data[1]]
            line = line_data[0].strip()
            register = line[-3:].strip()
            line = line.replace(register, needed_data)

        # strip any mid-line comments
        if ';' in line:
            line = line.split(';')[0]
            line = line.strip()

        # add patch if there's still any, reset data and store new offset
        if line.startswith('.offset'):
            if offset > 0 and len(instruction) > 0:
                patches.append((offset, instruction, patch_info))
                instruction = ''
                patch_info = ''
            offset = int(line.split(' ')[1][2:], 16)
            continue

        # handle branch offsets
        if line.startswith('b'):
            line_data = line.split(' ')
            branch_offset = int(line_data[1][2:], 16)
            diff = branch_offset - offset
            symbol = '+'
            if diff < 0:
                symbol = '' # if the diff is negative, it already has a - in front
            line = f"{line_data[0]} {symbol}{hex(diff)}"
        
        # handle adrp offsets
        # to make it easier to write patches, we can just write the absolute offset instead doing the page offset math
        if line.startswith('adrp'):
            line_data = line.split(', ')
            data_offset = line_data[1]
            line_data = line_data[0]
            data_offset = data_offset.replace(data_offset[-3:], '000', -1)
            page_offset = hex(offset)
            page_offset = page_offset.replace(page_offset[-3:], '000', -1)
            diff = int(data_offset, 16) - int(page_offset, 16)
            line = f"{line_data}, {hex(diff)}"

        # strip line of any remaining whitespace, add multi-line asm separator
        line = line.strip()
        instruction += line + '; '

    if offset > 0 and len(instruction) > 0:
        patches.append((offset, instruction, patch_info))

    if IS_RUNNING_FROM_SOURCE:
        for patch in patches:
            if len(patch[2]) > 0:
                print('\n' + patch[2])
            print(hex(patch[0]))
            print(patch[1])

    return patches


def preSetup(rand_state, settings):
    random.setstate(rand_state)
    asm_data = {}

    # store the actor ID of the randomized chest enemy
    if settings['randomize-enemies']:
        from RandomizerCore.randomizer_data import ENEMY_DATA
        asm_data['CHEST_ENEMY'] = f"#{random.choice(ENEMY_DATA['Chest_Enemies'])}"

    # since the patches are written last, we can just change the stealing setting to a boolean
    if settings['stealing'] == 'always':
        settings['stealing'] = True
    elif settings['stealing'] == 'never':
        settings['stealing'] = False

    return asm_data
