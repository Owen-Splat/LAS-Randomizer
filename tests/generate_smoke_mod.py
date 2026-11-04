"""Generate a real standalone integration-test seed using privately supplied game files.

Usage: python tests/generate_smoke_mod.py --romfs /path/to/romfs --output /new/output
The output must not exist. Never commit generated game assets or executables.
"""
import argparse
import copy
from pathlib import Path
import sys
import threading

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--romfs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seed', default='StandalonePR1')
    parser.add_argument('--platform', choices=('console', 'emulator'), default='emulator')
    arguments = parser.parse_args()
    if arguments.output.exists():
        raise ValueError('Choose a new, empty output path')
    from test_category_options import create_test_window, settings_manager, randomizer_data, GAME_LOGIC, APPLICATION
    from RandomizerCore.Native.builder import validate_input
    from RandomizerCore.shuffler import ItemShuffler
    from RandomizerCore.mod_generator import ModsProcess
    validate_input(arguments.romfs)
    test_window = create_test_window()
    for name in ('seashellsCheck', 'trendyCheck', 'shopCheck'):
        getattr(test_window.ui, name).setChecked(True)
    randomizer_settings = settings_manager.loadRandomizerSettings(test_window, arguments.seed)
    randomizer_settings.update({'platform': arguments.platform, 'owl-overworld-gifts': True, 'owl-dungeon-gifts': True, 'blupsanity': True, 'dungeon-items': 'none', 'create-spoiler': False})
    # Collect the shuffle result before generating the game files.
    shuffle_results = []
    errors = []
    shuffler = ItemShuffler(str(arguments.output), arguments.seed, 'basic', randomizer_settings, copy.deepcopy(randomizer_data.ITEM_DEFS), copy.deepcopy(GAME_LOGIC))
    shuffler.give_placements.connect(shuffle_results.append)
    shuffler.error.connect(errors.append)
    # Stop a stalled shuffle rather than waiting forever.
    shuffle_timeout = threading.Timer(90, shuffler.stop)
    shuffle_timeout.start()
    try:
        shuffler.run()
        APPLICATION.processEvents()
    finally:
        shuffle_timeout.cancel()
    if errors:
        raise RuntimeError('\n'.join(errors))
    if not shuffle_results or not shuffler.thread_active:
        raise RuntimeError('Shuffle did not finish within the test bound')
    placements, random_state = shuffle_results[0]
    if len([location for location in placements if location in GAME_LOGIC and GAME_LOGIC[location]['type'] == 'item']) != 344:
        raise ValueError('Incomplete placement')
    selected_locations = set(randomizer_data.SHOP_ITEMS + randomizer_data.TRENDY_REWARDS + randomizer_data.SHELL_LOCATIONS)
    if selected_locations & set(placements['force-vanilla']):
        raise ValueError('A selected category was left vanilla')
    mod_generator = ModsProcess(placements, str(arguments.romfs.resolve()), str(arguments.output.resolve()), copy.deepcopy(shuffler.item_defs), arguments.seed, random_state)
    mod_generator.error.connect(errors.append)
    mod_generator.run()
    APPLICATION.processEvents()
    if errors:
        raise RuntimeError('\n'.join(errors))
    print('Generated all 344 locations. Set LAS_TEST_MOD to: ' + str(Path(mod_generator.romfs_dir).parent))
if __name__ == '__main__':
    main()
