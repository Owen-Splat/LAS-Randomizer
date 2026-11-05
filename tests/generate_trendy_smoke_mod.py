from pathlib import Path
import copy
import os
import sys
import threading
from unittest.mock import patch

import argparse
parser = argparse.ArgumentParser(description='Generate a real standalone dev-port test seed.')
parser.add_argument('--romfs', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--seed', default='TrendyDevPort1')
parser.add_argument('--traps', default='None', choices=('None', 'Few', 'Many', 'Trapsanity'))
arguments = parser.parse_args()
if arguments.output.exists():
    raise ValueError('Choose a new output folder')
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
sys.argv[0] = str(root/'randomizer.py')
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
from PySide6.QtWidgets import QApplication
from RandomizerUI.main_window import MainWindow
from RandomizerCore import randomizer_data as data
from RandomizerCore.shuffler import ItemShuffler
from RandomizerCore.mod_generator import ModsProcess

app = QApplication([])
with patch('RandomizerUI.main_window.UpdateProcess.start'):
    window = MainWindow()
for name in ('Trendy Game',):
    window.ui.findCheckBox(name).setChecked(True)
window.ui.findLineEdit('SeedLine').setText(arguments.seed)
options = window.settings.fetch()
options.update(options.pop('Settings'))
options.update({'Traps': arguments.traps, 'Owl Gifts': 'All', 'Create Spoiler Log': False})
results = []; errors = []
shuffler = ItemShuffler(options, copy.deepcopy(data.ITEM_DEFS), copy.deepcopy(data.LOGIC_DEFS))
shuffler.give_placements.connect(results.append)
shuffler.error.connect(errors.append)
timer = threading.Timer(90, shuffler.stop)
timer.start()
try:
    shuffler.run(); app.processEvents()
finally:
    timer.cancel()
if errors: raise RuntimeError('\n'.join(errors))
if not results: raise RuntimeError('Dev shuffle did not produce a seed')
placements, state = results[0]
assert not set(data.TRENDY_REWARDS) & set(placements['force-vanilla'])
output = arguments.output.resolve()
generator = ModsProcess(placements, arguments.romfs.resolve(), output, shuffler.item_defs, options['Seed'], state)
generator.error.connect(errors.append)
generator.run(); app.processEvents()
if errors: raise RuntimeError('\n'.join(errors))
print('Real dev seed generated at', generator.romfs_dir.parent)
