from RandomizerCore.Paths.randomizer_paths import IS_RUNNING_FROM_SOURCE
import os


def generateSpoilerLog(placements, logic_defs, out_dir, seed):
    # Make the output directory if it doesnt exist
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    
    regions = {'mabe-village': [], 'toronbo-shores': [], 'mysterious-woods': [], 'koholint-prairie': [], 'tabahl-wasteland': [], 'ukuku-prairie': [], 'sign-maze': [], 'goponga-swamp': [], 'taltal-heights': [], 'marthas-bay': [], 'kanalet-castle': [], 'pothole-field': [], 'animal-village': [], 'yarna-desert': [], 'ancient-ruins': [], 'rapids-ride': [], 'taltal-mountains-east': [], 'taltal-mountains-west': [], 'color-dungeon': [], 'tail-cave': [], 'bottle-grotto': [], 'key-cavern': [], 'angler-tunnel': [], 'catfish-maw': [], 'face-shrine': [], 'eagle-tower': [], 'turtle-rock': []}
    
    for key in logic_defs:
        if not key.startswith('starting-item') and logic_defs[key]['type'] in ['item', 'follower']:
            regions[logic_defs[key]['spoiler-region']].append(key)
    
    with open(f'{out_dir}/spoiler_{seed}.txt', 'w') as output:
        output.write('settings:\n')
        sets = list(placements['settings'])
        sets.sort()
        for setting in sets:
            if setting not in ('excluded-locations', 'starting-items'):
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
                    index = placements['indexes'][location]
                index = f'[{index}]' if (IS_RUNNING_FROM_SOURCE and index > -1) else ''
                if location.startswith('starting-dungeon-item'):
                    continue
                if item.endswith('trap'):
                    item = 'trap'
                output.write('    {0}:  {1}{2}\n'.format(location, item, index))
