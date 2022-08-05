import Tools.oead_tools as oead_tools
from Randomizers import data



def makeConditions(sheet, placements):
    """Create new condition sets for the seashell sensor to work with Dampe, Rapids guy, Fishing Guy, and Seashell mansion"""

    dampe_condition = oead_tools.createCondition('DampeShellsComplete', [(9, 'true')])
    dampe_locations = ['dampe-page-1', 'dampe-heart-challenge', 'dampe-page-2', 'dampe-bottle-challenge', 'dampe-final']
    for location in dampe_locations:
        if placements[location] == 'seashell':
            dampe_condition['conditions'].append({'category': 2, 'parameter': f"Seashell:{placements['indexes'][location]}"})
    sheet['values'].append(dampe_condition)

    rapids_condition = oead_tools.createCondition('RapidsShellsComplete', [(9, 'true')])
    rapids_locations = ['rapids-race-30', 'rapids-race-35', 'rapids-race-45']
    for location in rapids_locations:
        if placements[location] == 'seashell':
            rapids_condition['conditions'].append({'category': 2, 'parameter': f"Seashell:{placements['indexes'][location]}"})
    sheet['values'].append(rapids_condition)

    fishing_condition = oead_tools.createCondition('FishingShellsComplete', [(9, 'true')])
    fishing_locations = ['fishing-orange', 'fishing-cheep-cheep', 'fishing-ol-baron', 'fishing-loose', 'fishing-50', 'fishing-100', 'fishing-150']
    for location in fishing_locations:
        if placements[location] == 'seashell':
            fishing_condition['conditions'].append({'category': 2, 'parameter': f"Seashell:{placements['indexes'][location]}"})
    sheet['values'].append(fishing_condition)

    mansion_condition = oead_tools.createCondition('MansionShellsComplete', [(9, 'true')])
    mansion_locations = ['5-seashell-reward', '15-seashell-reward', '30-seashell-reward', '40-seashell-reward', '50-seashell-reward']
    for location in mansion_locations:
        if placements[location] == 'seashell':
            mansion_condition['conditions'].append({'category': 2, 'parameter': f"Seashell:{placements['indexes'][location]}"})
    sheet['values'].append(mansion_condition)



def editConditions(condition, placements):
    """Makes needed changes to conditions, such as making Marin staying in Mabe and the shop not sell shields until you find one"""
    
    # Make sure Marin always stays in the village even if you trade for the pineapple
    if condition['symbol'] == 'MarinVillageStay':
        condition['conditions'].pop(1)

    # Make the shop not sell shields until you find one
    if condition['symbol'] == 'ShopShieldCondition':
        condition['conditions'][0] = {'category': 1, 'parameter': data.SHIELD_FOUND_FLAG}
    
    # Make the animals in Animal village not be in the ring, which they would because of WalrusAwaked getting set
    if condition['symbol'] == 'AnimalPop':
        condition['conditions'][0] = {'category': 9, 'parameter': 'false'}
    
    # Make Grandma Yahoo's broom invisible until you give her the broom
    if condition['symbol'] == 'BroomInvisible':
        condition['conditions'].pop(0)
    
    # Remove the condition for bombs in the shop if the unlocked-bombs setting is on
    if condition['symbol'] == 'ShopBombCondition':
        if placements['settings']['unlocked-bombs']:
            condition['conditions'][0] = {'category': 9, 'parameter': 'true'}
        if placements['settings']['shuffle-bombs']:
            condition['conditions'][0] = {'category': 1, 'parameter': data.BOMBS_FOUND_FLAG}
    
    # # Edit the condition for the shovel since it is shuffled
    # if condition['symbol'] == 'ShopShovelCondition':
    #     condition['conditions'].pop(0)
    #     condition['conditions'][0] = {'category': 1, 'parameter': '!ShopShovelGet'}
    
    # # Edit the condition for the bow since it is shuffled
    # if condition['symbol'] == 'ShopBowCondition':
    #     condition['conditions'][0] = {'category': 1, 'parameter': 'ShopShovelGet'}
    #     condition['conditions'][1] = {'category': 1, 'parameter': '!ShopBowGet'}
