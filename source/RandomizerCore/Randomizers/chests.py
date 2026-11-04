import RandomizerCore.Tools.event_tools as event_tools
from RandomizerCore.Randomizers import item_get
# from RandomizerCore.Randomizers import data



def writeChestEvent(flowchart):
    """Writes an itemKey comparision and itemGet chain and connects it to the chest open events"""

    auto_save = event_tools.createActionEvent(flowchart, 'GameControl', 'RequestAutoSave', {}, None)

    sword_get = item_get.insertItemGetAnimation(flowchart, 'SwordLv1', -1 , None, auto_save)
    sword_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'SwordLv1'},
        {0: sword_get, 1: 'Event33'})
    
    shield_get = item_get.insertItemGetAnimation(flowchart, 'Shield', -1, None, auto_save)
    shield_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Shield'},
        {0: shield_get, 1: sword_check})

    bracelet_get = item_get.insertItemGetAnimation(flowchart, 'PowerBraceletLv1', -1, None, auto_save)
    bracelet_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'PowerBraceletLv1'},
        {0: bracelet_get, 1: shield_check})

    powder_capacity_get = item_get.insertItemGetAnimation(flowchart, 'MagicPowder_MaxUp', -1, None, auto_save)
    powder_capacity_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'MagicPowder_MaxUp'},
        {0: powder_capacity_get, 1: bracelet_check})

    bomb_capacity_get = item_get.insertItemGetAnimation(flowchart, 'Bomb_MaxUp', -1, None, auto_save)
    bomb_capacity_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Bomb_MaxUp'},
        {0: bomb_capacity_get, 1: powder_capacity_check})

    arrow_capacity_get = item_get.insertItemGetAnimation(flowchart, 'Arrow_MaxUp', -1, None, auto_save)
    arrow_capacity_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Arrow_MaxUp'},
        {0: arrow_capacity_get, 1: bomb_capacity_check})

    red_tunic_get = item_get.insertItemGetAnimation(flowchart, 'ClothesRed', -1, None, auto_save)
    red_tunic_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'ClothesRed'},
        {0: red_tunic_get, 1: arrow_capacity_check})

    blue_tunic_get = item_get.insertItemGetAnimation(flowchart, 'ClothesBlue', -1, None, auto_save)
    blue_tunic_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'ClothesBlue'},
        {0: blue_tunic_get, 1: red_tunic_check})
    
    cello_get = item_get.insertItemGetAnimation(flowchart, 'FullMoonCello', -1, None, auto_save)
    cello_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'FullMoonCello'},
        {0: cello_get, 1: blue_tunic_check})
    
    harp_get = item_get.insertItemGetAnimation(flowchart, 'SurfHarp', -1, None, auto_save)
    harp_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'SurfHarp'},
        {0: harp_get, 1: cello_check})

    yoshi_get = item_get.insertItemGetAnimation(flowchart, 'YoshiDoll', -1, None, auto_save)
    yoshi_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'YoshiDoll'},
        {0: yoshi_get, 1: harp_check})

    ribbon_get = item_get.insertItemGetAnimation(flowchart, 'Ribbon', -1, None, auto_save)
    ribbon_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Ribbon'},
        {0: ribbon_get, 1: yoshi_check})

    dog_food_get = item_get.insertItemGetAnimation(flowchart, 'DogFood', -1, None, auto_save)
    dog_food_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'DogFood'},
        {0: dog_food_get, 1: ribbon_check})

    bananas_get = item_get.insertItemGetAnimation(flowchart, 'Bananas', -1, None, auto_save)
    bananas_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Bananas'},
        {0: bananas_get, 1: dog_food_check})

    stick_get = item_get.insertItemGetAnimation(flowchart, 'Stick', -1, None, auto_save)
    stick_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Stick'},
        {0: stick_get, 1: bananas_check})

    honeycomb_get = item_get.insertItemGetAnimation(flowchart, 'Honeycomb', -1, None, auto_save)
    honeycomb_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Honeycomb'},
        {0: honeycomb_get, 1: stick_check})

    pineapple_get = item_get.insertItemGetAnimation(flowchart, 'Pineapple', -1, None, auto_save)
    pineapple_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Pineapple'},
        {0: pineapple_get, 1: honeycomb_check})

    hibiscus_get = item_get.insertItemGetAnimation(flowchart, 'Hibiscus', -1, None, auto_save)
    hibiscus_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Hibiscus'},
        {0: hibiscus_get, 1: pineapple_check})

    letter_get = item_get.insertItemGetAnimation(flowchart, 'Letter', -1, None, auto_save)
    letter_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Letter'},
        {0: letter_get, 1: hibiscus_check})

    broom_get = item_get.insertItemGetAnimation(flowchart, 'Broom', -1, None, auto_save)
    broom_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Broom'},
        {0: broom_get, 1: letter_check})

    hook_get = item_get.insertItemGetAnimation(flowchart, 'FishingHook', -1, None, auto_save)
    hook_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'FishingHook'},
        {0: hook_get, 1: broom_check})

    necklace_get = item_get.insertItemGetAnimation(flowchart, 'PinkBra', -1, None, auto_save)
    necklace_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'PinkBra'},
        {0: necklace_get, 1: hook_check})

    scale_get = item_get.insertItemGetAnimation(flowchart, 'MermaidsScale', -1, None, auto_save)
    scale_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'MermaidsScale'},
        {0: scale_get, 1: necklace_check})
    
    lens_get = item_get.insertItemGetAnimation(flowchart, 'MagnifyingLens', -1, None, auto_save)
    lens_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'MagnifyingLens'},
        {0: lens_get, 1: scale_check})
    
    zap_get = item_get.insertItemGetAnimation(flowchart, 'ZapTrap', -1, None, auto_save)
    zap_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'ZapTrap'},
        {0: zap_get, 1: lens_check})
    
    drown_get = item_get.insertItemGetAnimation(flowchart, 'DrownTrap', -1, None, auto_save)
    drown_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'DrownTrap'},
        {0: drown_get, 1: zap_check})
    
    squish_get = item_get.insertItemGetAnimation(flowchart, 'SquishTrap', -1, None, auto_save)
    squish_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'SquishTrap'},
        {0: squish_get, 1: drown_check})
    
    deathball_get = item_get.insertItemGetAnimation(flowchart, 'DeathballTrap', -1, None, auto_save)
    deathball_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'DeathballTrap'},
        {0: deathball_get, 1: squish_check})
    
    quake_get = item_get.insertItemGetAnimation(flowchart, 'QuakeTrap', -1, None, auto_save)
    quake_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'QuakeTrap'},
        {0: quake_get, 1: deathball_check})
    
    # hydro_get = item_get.insertItemGetAnimation(flowchart, 'HydroTrap', -1, None, auto_save)
    # hydro_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    #     {'value1': 'itemKey', 'value2': 'HydroTrap'},
    #     {0: hydro_get, 1: quake_check})
    
    bomb_get = item_get.insertItemGetAnimation(flowchart, 'Bomb', -1, None, auto_save)
    bomb_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Bomb'},
        {0: bomb_get, 1: quake_check})
    
    powder_get = item_get.insertItemGetAnimation(flowchart, 'MagicPowder', -1, None, auto_save)
    powder_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'MagicPowder'},
        {0: powder_get, 1: bomb_check})
    
    # CompareInt normally returns True if value1 > value 2, but we use ASM to change it to if value1 == value2
    bottle_get = item_get.insertItemGetAnimation(flowchart, 'Bottle', 1, None, auto_save)
    index_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareInt',
        {'value1': 'itemIndex', 'value2': 1},
        {0: bottle_get, 1: powder_check})
    bottle_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
        {'value1': 'itemKey', 'value2': 'Bottle'},
        {0: index_check, 1: powder_check})
    
    # rooster_fork = event_tools.createForkEvent(flowchart, None, [
    #     event_tools.createActionChain(flowchart, None, [
    #         ('Dialog', 'Show', {'message': 'Scenario:GetFlyingCocco'}),
    #         ('FlyingCucco[FlyCocco]', 'StopTailorOtherChannel', {'channel': 'FlyingCucco_get', 'index': 0}),
    #         ('FlyingCucco[FlyCocco]', 'PlayAnimation', {'blendTime': 0.0, 'name': 'ev_glad_ed'}),
    #         ('FlyingCucco[FlyCocco]', 'CancelCarried', {}),
    #         ('FlyingCucco[FlyCocco]', 'Join', {}),
    #         # ('Link', 'SetDisablePowerUpEffect', {'effect': False, 'materialAnim': False, 'sound': False}),
    #         ('GameControl', 'RequestAutoSave', {})
    #     ], None),
    #     event_tools.createActionChain(flowchart, None, [
    #         ('Timer', 'Wait', {'time': 3.3})
    #         # ('Audio', 'PlayZoneBGM', {'stopbgm': True})
    #     ], None)
    # ], auto_save)[0]
    # rooster_get = event_tools.createActionChain(flowchart, None, [
    #     ('EventFlags', 'SetFlag', {'symbol': data.ROOSTER_FOUND_FLAG, 'value': True}),
    #     ('FlyingCucco[FlyCocco]', 'Activate', {}),
    #     ('FlyingCucco[FlyCocco]', 'PlayAnimation', {'blendTime': 0.0, 'name': 'FlyingCocco_get'}),
    #     ('Link', 'AimCompassPoint', {'direction': 0, 'duration': 0.1, 'withoutTurn': False}),
    #     ('Link', 'PlayAnimationEx', {'time': 0.0, 'blendTime': 0.0, 'name': 'item_get_lp'}),
    #     ('FlyingCucco[FlyCocco]', 'BeCarried', {}),
    #     ('Link', 'LookAtItemGettingPlayer', {'chaseRatio': 0.1, 'distanceOffset': 0.0, 'duration': 0.7}),
    #     ('Audio', 'PlayOneshotSystemSE', {'label': 'SE_PL_ITEM_GET_LIGHT', 'volume': 1.0, 'pitch': 1.0})
    # ], rooster_fork)
    # rooster_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    #     {'value1': 'itemKey', 'value2': 'Rooster'},
    #     {0: rooster_get, 1: medicine_check})

    # shadow_get = item_get.insertItemGetAnimation(flowchart, 'ShadowLink', -1, None, auto_save)
    # shadow_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    # {'value1': 'itemKey', 'value2': 'ShadowLink'},
    # {0: shadow_get, 1: rooster_check})

    # add this chain to TreasureBox_Open and TreasureBox_ShockOpen
    event_tools.insertEventAfter(flowchart, 'Event32', bottle_check)
    event_tools.insertEventAfter(flowchart, 'Event28', bottle_check)
    
    # now make the rest of the items also request an autosave
    event_tools.insertEventAfter(flowchart, 'Event40', auto_save)
    event_tools.insertEventAfter(flowchart, 'Event5', auto_save)

    # make the D6 pot chest check if it contains an enemy
    event_tools.insertEventAfter(flowchart, 'TreasureBox_ShockOpen', 'Event27')
    event_tools.insertEventAfter(flowchart, 'Event15', 'Event28')
    check_enemy = event_tools.createSwitchEvent(flowchart, 'TreasureBox', 'ContainsEnemy',
        {}, {0: 'Event15', 1: 'Event42'})
    event_tools.insertEventAfter(flowchart, 'Event27', check_enemy)



def makeChestsFaster(flowchart):
    '''Speeds up the animation and gives control back to the player a bit sooner'''

    # remove the cameraLookAt event and the secret unlocked music
    del event_tools.findEvent(flowchart, 'Event44').data.forks[0]
    event_tools.insertEventAfter(flowchart, 'Event52', None)

    # now edit Link to move 3x faster if he is in the way of the chest
    # event_tools.findEvent(flowchart, 'Event46').data.params.data['speed'] = 3
    # event_tools.findEvent(flowchart, 'Event46').data.params.data = {
    #     'speed': 3,
    #     'distance': 1.5,
    #     'actor': 'TreasureBox',
    #     'timeOut': 1.0 # idk if there is any instance where timeOut: 7.0 actually matters but just in case we set it to 1.0
    # }