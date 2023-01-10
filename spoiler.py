# MIT License

# Copyright (c) 2021 la-switch

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import os


def generateSpoilerLog(placements, logicDefs, outputDir, seedName):
    # Make the output directory if it doesnt exist
    if not os.path.exists(outputDir):
        os.makedirs(outputDir)
    
    regions = {'mabe-village': [], 'toronbo-shores': [], 'mysterious-woods': [], 'koholint-prairie': [], 'tabahl-wasteland': [], 'ukuku-prairie': [], 'sign-maze': [], 'goponga-swamp': [], 'taltal-heights': [], 'marthas-bay': [], 'kanalet-castle': [], 'pothole-field': [], 'animal-village': [], 'yarna-desert': [], 'ancient-ruins': [], 'rapids-ride': [], 'taltal-mountains-east': [], 'taltal-mountains-west': [], 'color-dungeon': [], 'tail-cave': [], 'bottle-grotto': [], 'key-cavern': [], 'angler-tunnel': [], 'catfish-maw': [], 'face-shrine': [], 'eagle-tower': [], 'turtle-rock': []}
    
    for key in logicDefs:
        if logicDefs[key]['type'] in ['item', 'follower']:
            regions[logicDefs[key]['spoiler-region']].append(key)
    
    with open(f'{outputDir}/spoiler_{seedName}.txt', 'w') as output:
        for key in regions:
            output.write(f'{key}:\n')
            for location in regions[key]:
                output.write('  {0}: {1}\n'.format(location, placements[location]))
        
        output.write('\nsettings:\n')
        for setting in placements['settings']:
            if setting != 'excluded-locations':
                output.write(f'  {setting}: {placements["settings"][setting]}\n')
        
        output.write('\nstarting-instruments:\n')
        for inst in placements['starting-instruments']:
            output.write(f'  {inst}\n')
        
        output.write('\nexcluded-locations:\n')
        for location in placements['force-junk']:
            output.write(f'  {location}\n')