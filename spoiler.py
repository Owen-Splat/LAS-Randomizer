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
        for key in regions:
            output.write(f'{key}:\n')
            for location in regions[key]:
                output.write('  {0}: {1}\n'.format(location, placements[location]))
        
        output.write('\nsettings:\n')
        for setting in placements['settings']:
            if setting not in ('excluded-locations', 'starting-items'):
                output.write(f'  {setting}: {placements["settings"][setting]}\n')
                
        output.write('\ndungeon-entrances:\n')
        for dun in placements['dungeon-entrances']:
            output.write(f'  {dun} -> {placements["dungeon-entrances"][dun]}\n')

        output.write('\nexcluded-locations:\n')
        for location in placements['force-junk']:
            output.write(f'  {location}\n')
        
        output.write('\nstarting-items:\n')
        for item in placements['starting-items']:
            output.write(f'  {item}\n')