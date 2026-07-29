from RandomizerCore.Paths.randomizer_paths import IS_RUNNING_FROM_SOURCE
from pathlib import Path


def generateSpoilerLog(placements, logic_defs: dict, out_dir: Path, seed: str):
    # Make the output directory if it doesnt exist
    if not out_dir.exists():
        out_dir.mkdir(parents=True)

    regions = {'mabe-village': [], 'toronbo-shores': [], 'mysterious-woods': [], 'koholint-prairie': [], 'tabahl-wasteland': [], 'ukuku-prairie': [], 'sign-maze': [], 'goponga-swamp': [], 'taltal-heights': [], 'marthas-bay': [], 'kanalet-castle': [], 'pothole-field': [], 'animal-village': [], 'yarna-desert': [], 'ancient-ruins': [], 'rapids-ride': [], 'taltal-mountains-east': [], 'taltal-mountains-west': [], 'color-dungeon': [], 'tail-cave': [], 'bottle-grotto': [], 'key-cavern': [], 'angler-tunnel': [], 'catfish-maw': [], 'face-shrine': [], 'eagle-tower': [], 'turtle-rock': []}

    for key in logic_defs:
        if not key.startswith('starting-item') and logic_defs[key]['type'] in ['item', 'follower']:
            regions[logic_defs[key]['spoiler-region']].append(key)

    with open(out_dir / f"spoiler_{seed}.txt", 'w') as output:
        output.write('settings:\n')
        sets = list(placements['settings'])
        sets.sort()
        for setting in sets:
            if setting not in ('Excluded Locations', 'Starting Gear'):
                output.write(f'    {setting}:  {placements["settings"][setting]}\n')

        output.write('\nstarting-items:\n')
        items = list(placements['starting-items'])
        items.sort()
        for item in items:
            output.write(f'    {item}\n')

        output.write('\nexcluded-locations:\n')
        junk = list(placements['force-junk'])
        junk.sort()
        for location in junk:
            output.write(f'    {location}\n')

        output.write('\ndungeon-entrances:\n')
        for dun in placements['dungeon-entrances']:
            output.write(f'    {dun} -> {placements["dungeon-entrances"][dun]}\n')

        output.write('\n')
        for key in regions:
            output.write(f'{key}:\n')
            for location in regions[key]:
                item = placements[location]
                index = -1
                if location in placements['indexes']:
                    if not item.startswith(('map', 'compass', 'stone-beak', 'key', 'nightmare-key')):
                        index = placements['indexes'][location]
                index = f'[{index}]' if (IS_RUNNING_FROM_SOURCE and index > -1) else ''
                if item.endswith('trap'):
                    item = 'trap'
                output.write('    {0}:  {1}{2}\n'.format(location, item, index))
