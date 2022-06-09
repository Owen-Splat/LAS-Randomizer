import Tools.oead_tools as oead_tools



def make_conditions(sheet, placements, shieldFlag):
    # Create new condition sets for the seashell sensor to work with Dampe, Rapids guy, Fishing Guy, and Seashell mansion
    dampeCondition = oead_tools.createCondition('DampeShellsComplete', [(9, 'true')])
    dampeLocations = ['dampe-page-1', 'dampe-heart-challenge', 'dampe-page-2', 'dampe-bottle-challenge', 'dampe-final']
    for location in dampeLocations:
        if placements[location] == 'seashell':
            dampeCondition['conditions'].append({'category': 2, 'parameter': f"Seashell:{placements['indexes'][location]}"})
    sheet['values'].append(dampeCondition)

    rapidsCondition = oead_tools.createCondition('RapidsShellsComplete', [(9, 'true')])
    rapidsLocations = ['rapids-race-30', 'rapids-race-35', 'rapids-race-45']
    for location in rapidsLocations:
        if placements[location] == 'seashell':
            rapidsCondition['conditions'].append({'category': 2, 'parameter': f"Seashell:{placements['indexes'][location]}"})
    sheet['values'].append(rapidsCondition)

    fishingCondition = oead_tools.createCondition('FishingShellsComplete', [(9, 'true')])
    fishingLocations = ['fishing-orange', 'fishing-cheep-cheep', 'fishing-ol-baron', 'fishing-loose', 'fishing-50', 'fishing-100', 'fishing-150']
    for location in fishingLocations:
        if placements[location] == 'seashell':
            fishingCondition['conditions'].append({'category': 2, 'parameter': f"Seashell:{placements['indexes'][location]}"})
    sheet['values'].append(fishingCondition)

    mansionCondition = oead_tools.createCondition('MansionShellsComplete', [(9, 'true')])
    mansionLocations = ['5-seashell-reward', '15-seashell-reward', '30-seashell-reward', '40-seashell-reward', '50-seashell-reward']
    for location in mansionLocations:
        if placements[location] == 'seashell':
            mansionCondition['conditions'].append({'category': 2, 'parameter': f"Seashell:{placements['indexes'][location]}"})
    sheet['values'].append(mansionCondition)



def edit_conditions(condition, placements, shieldFlag):
    # Make sure Marin always stays in the village even if you trade for the pineapple
    if condition['symbol'] == 'MarinVillageStay':
        condition['conditions'].pop(1)

    # Make the shop not sell shields until you find one
    if condition['symbol'] == 'ShopShieldCondition':
        condition['conditions'][0] = {'category': 1, 'parameter': shieldFlag}
    
    # Make the animals in Animal village not be in the ring, which they would because of WalrusAwaked getting set
    if condition['symbol'] == 'AnimalPop':
        condition['conditions'][0] = {'category': 9, 'parameter': 'false'}

    # Remove the condition for bombs in the shop if the unlocked-bombs setting is on
    if condition['symbol'] == 'ShopBombCondition' and placements['settings']['unlocked-bombs']:
        condition['conditions'][0] = {'category': 9, 'parameter': 'true'}
    
    # ### BOMB SHOP TESTING
    # # Make the shop not sell bombs until you find one
    # if condition['symbol'] == 'ShopBombCondition':
    #     condition['conditions'][0] = {'category': 9, 'parameter': 'Bomb'}

