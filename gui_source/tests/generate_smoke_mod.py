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
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--romfs',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--seed',default='StandalonePR1')
    parser.add_argument('--platform',choices=('console','emulator'),default='emulator')
    args=parser.parse_args()
    if args.output.exists():raise ValueError('Choose a new, empty output path')
    from test_category_options import window,settings,data,LOGIC,APP
    from RandomizerCore.Native.builder import validate_input
    from RandomizerCore.shuffler import ItemShuffler
    from RandomizerCore.mod_generator import ModsProcess
    validate_input(args.romfs)
    w=window()
    for name in ('seashellsCheck','trendyCheck','shopCheck'):getattr(w.ui,name).setChecked(True)
    mod=settings.loadRandomizerSettings(w,args.seed)
    mod.update({'platform':args.platform,'owl-overworld-gifts':True,'owl-dungeon-gifts':True,'blupsanity':True,'dungeon-items':'none','create-spoiler':False})
    result=[];errors=[]
    shuffler=ItemShuffler(str(args.output),args.seed,'basic',mod,copy.deepcopy(data.ITEM_DEFS),copy.deepcopy(LOGIC))
    shuffler.give_placements.connect(result.append);shuffler.error.connect(errors.append)
    timer=threading.Timer(90,shuffler.stop);timer.start()
    try:shuffler.run();APP.processEvents()
    finally:timer.cancel()
    if errors:raise RuntimeError('\n'.join(errors))
    if not result or not shuffler.thread_active:raise RuntimeError('Shuffle did not finish within the test bound')
    placements,state=result[0]
    if len([k for k in placements if k in LOGIC and LOGIC[k]['type']=='item'])!=344:raise ValueError('Incomplete placement')
    sources=set(data.SHOP_ITEMS+data.TRENDY_REWARDS+data.SHELL_LOCATIONS)
    if sources&set(placements['force-vanilla']):raise ValueError('A selected category was left vanilla')
    process=ModsProcess(placements,str(args.romfs.resolve()),str(args.output.resolve()),copy.deepcopy(shuffler.item_defs),args.seed,state)
    process.error.connect(errors.append);process.run();APP.processEvents()
    if errors:raise RuntimeError('\n'.join(errors))
    print('Generated all 344 locations. Set LAS_TEST_MOD to: '+str(Path(process.romfs_dir).parent))

if __name__=='__main__':main()
