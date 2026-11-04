import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import item_get, data



def changeRewards(flowchart):
    """Adds a itemKey comparison and itemGet animation chain to when you open presents"""
    
    sword_get = item_get.insertItemGetAnimation(flowchart, 'SwordLv1', -1 , None, 'Event0')
    sword_content_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'SwordLv1'},
        {0: sword_get, 1: 'Event4'})
    
    shield_get = item_get.insertItemGetAnimation(flowchart, 'Shield', -1, None, 'Event0')
    shield_content_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Shield'},
        {0: shield_get, 1: sword_content_check})

    bracelet_get = item_get.insertItemGetAnimation(flowchart, 'PowerBraceletLv1', -1, None, 'Event0')
    bracelet_content_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'PowerBraceletLv1'},
        {0: bracelet_get, 1: shield_content_check})

    powder_capacity_get = item_get.insertItemGetAnimation(flowchart, 'MagicPowder_MaxUp', -1, None, 'Event0')
    powder_capacity_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'MagicPowder_MaxUp'},
        {0: powder_capacity_get, 1: bracelet_content_check})

    bomb_capacity_get = item_get.insertItemGetAnimation(flowchart, 'Bomb_MaxUp', -1, None, 'Event0')
    bomb_capacity_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Bomb_MaxUp'},
        {0: bomb_capacity_get, 1: powder_capacity_check})

    arrow_capacity_get = item_get.insertItemGetAnimation(flowchart, 'Arrow_MaxUp', -1, None, 'Event0')
    arrow_capacity_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Arrow_MaxUp'},
        {0: arrow_capacity_get, 1: bomb_capacity_check})

    red_tunic_get = item_get.insertItemGetAnimation(flowchart, 'ClothesRed', -1, None, 'Event0')
    red_tunic_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'ClothesRed'},
        {0: red_tunic_get, 1: arrow_capacity_check})

    blue_tunic_get = item_get.insertItemGetAnimation(flowchart, 'ClothesBlue', -1, None, 'Event0')
    blue_tunic_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'ClothesBlue'},
        {0: blue_tunic_get, 1: red_tunic_check})

    cello_get = item_get.insertItemGetAnimation(flowchart, 'FullMoonCello', -1, None, 'Event0')
    cello_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'FullMoonCello'},
        {0: cello_get, 1: blue_tunic_check})

    harp_get = item_get.insertItemGetAnimation(flowchart, 'SurfHarp', -1, None, 'Event0')
    harp_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'SurfHarp'},
        {0: harp_get, 1: cello_check})

    yoshi_get = item_get.insertItemGetAnimation(flowchart, 'YoshiDoll', -1, None, 'Event0')
    yoshi_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'YoshiDoll'},
        {0: yoshi_get, 1: harp_check})

    ribbon_get = item_get.insertItemGetAnimation(flowchart, 'Ribbon', -1, None, 'Event0')
    ribbon_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Ribbon'},
        {0: ribbon_get, 1: yoshi_check})

    dog_food_get = item_get.insertItemGetAnimation(flowchart, 'DogFood', -1, None, 'Event0')
    dog_food_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'DogFood'},
        {0: dog_food_get, 1: ribbon_check})

    bananas_get = item_get.insertItemGetAnimation(flowchart, 'Bananas', -1, None, 'Event0')
    bananas_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Bananas'},
        {0: bananas_get, 1: dog_food_check})

    stick_get = item_get.insertItemGetAnimation(flowchart, 'Stick', -1, None, 'Event0')
    stick_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Stick'},
        {0: stick_get, 1: bananas_check})

    honeycomb_get = item_get.insertItemGetAnimation(flowchart, 'Honeycomb', -1, None, 'Event0')
    honeycomb_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Honeycomb'},
        {0: honeycomb_get, 1: stick_check})

    pineapple_get = item_get.insertItemGetAnimation(flowchart, 'Pineapple', -1, None, 'Event0')
    pineapple_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Pineapple'},
        {0: pineapple_get, 1: honeycomb_check})

    hibiscus_get = item_get.insertItemGetAnimation(flowchart, 'Hibiscus', -1, None, 'Event0')
    hibiscus_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Hibiscus'},
        {0: hibiscus_get, 1: pineapple_check})

    letter_get = item_get.insertItemGetAnimation(flowchart, 'Letter', -1, None, 'Event0')
    letter_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Letter'},
        {0: letter_get, 1: hibiscus_check})

    broom_get = item_get.insertItemGetAnimation(flowchart, 'Broom', -1, None, 'Event0')
    broom_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Broom'},
        {0: broom_get, 1: letter_check})

    hook_get = item_get.insertItemGetAnimation(flowchart, 'FishingHook', -1, None, 'Event0')
    hook_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'FishingHook'},
        {0: hook_get, 1: broom_check})

    necklace_get = item_get.insertItemGetAnimation(flowchart, 'PinkBra', -1, None, 'Event0')
    necklace_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'PinkBra'},
        {0: necklace_get, 1: hook_check})

    scale_get = item_get.insertItemGetAnimation(flowchart, 'MermaidsScale', -1, None, 'Event0')
    scale_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'MermaidsScale'},
        {0: scale_get, 1: necklace_check})

    lens_get = item_get.insertItemGetAnimation(flowchart, 'MagnifyingLens', -1, None, 'Event0')
    lens_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'MagnifyingLens'},
        {0: lens_get, 1: scale_check})

    zap_get = item_get.insertItemGetAnimation(flowchart, 'ZapTrap', -1, None, 'Event0')
    zap_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'ZapTrap'},
        {0: zap_get, 1: lens_check})
    
    drown_get = item_get.insertItemGetAnimation(flowchart, 'DrownTrap', -1, None, 'Event0')
    drown_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'DrownTrap'},
        {0: drown_get, 1: zap_check})
    
    squish_get = item_get.insertItemGetAnimation(flowchart, 'SquishTrap', -1, None, 'Event0')
    squish_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'SquishTrap'},
        {0: squish_get, 1: drown_check})
    
    deathball_get = item_get.insertItemGetAnimation(flowchart, 'DeathballTrap', -1, None, 'Event0')
    deathball_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'DeathballTrap'},
        {0: deathball_get, 1: squish_check})
    
    quake_get = item_get.insertItemGetAnimation(flowchart, 'QuakeTrap', -1, None, 'Event0')
    quake_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'QuakeTrap'},
        {0: quake_get, 1: deathball_check})
    
    # hydro_get = item_get.insertItemGetAnimation(flowchart, 'HydroTrap', -1, None, 'Event0')
    # hydro_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    #     {'value1': 'itemKey', 'value2': 'HydroTrap'},
    #     {0: hydro_get, 1: quake_check})
    
    bomb_get = item_get.insertItemGetAnimation(flowchart, 'Bomb', -1, None, 'Event0')
    bomb_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Bomb'},
        {0: bomb_get, 1: quake_check})
    
    powder_get = item_get.insertItemGetAnimation(flowchart, 'MagicPowder', -1, None, 'Event0')
    powder_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'MagicPowder'},
        {0: powder_get, 1: bomb_check})
    
    # CompareInt normally returns True if value1 > value 2, but we use ASM to change it to if value1 == value2
    bottle_get = item_get.insertItemGetAnimation(flowchart, 'Bottle', 1, None, 'Event0')
    index_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt',
        {'value1': 'itemIndex', 'value2': 1},
        {0: bottle_get, 1: powder_check})
    bottle_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Bottle'},
        {0: index_check, 1: powder_check})
    
    event_tools.insertEventAfter(flowchart, 'Event25', bottle_check)



def makeEventChanges(flowchart, placements):
    # 40 shells, doesn't use a present box
    event_tools.findEvent(flowchart, 'Event65').data.forks.pop(0)

    event_tools.insertEventAfter(flowchart, 'Event64', 'Event65')

    # Remove the thing to show Link's sword because it will show L1 sword if he has none. 
    sword_check1 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag', {'symbol': data.SWORD_FOUND_FLAG}, {0: 'Event65', 1: 'Event64'})
    event_tools.insertEventAfter(flowchart, 'Event80', sword_check1)

    # However, leave it the 2nd time if he's going to get one here.
    if placements['40-seashell-reward'] != 'sword':
        sword_check2 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag', {'symbol': data.SWORD_FOUND_FLAG}, {0: 'Event48', 1: 'Event47'})
        event_tools.insertEventAfter(flowchart, 'Event54', sword_check2)
    
    # Special case, if there is a sword here, then actually give them item before the end of the animation so it looks like the vanilla cutscene :)
    if placements['40-seashell-reward'] == 'sword':
        early_give_sword1 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv1', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
        early_give_sword2 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv2', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
        sword_check3 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag', {'symbol': data.SWORD_FOUND_FLAG}, {0: early_give_sword1, 1: early_give_sword2})
        event_tools.insertEventAfter(flowchart, 'Event74', sword_check3)
    else:
        event_tools.insertEventAfter(flowchart, 'Event74', 'Event19')

