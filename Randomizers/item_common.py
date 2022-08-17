import Tools.event_tools as event_tools
from Randomizers import item_get



def addCompareStringChain(flowchart):
    """Adds a chain of CompareString to compare the itemKey parameter to use for custom item get sequences"""

    sword_get = item_get.insertItemGetAnimation(flowchart, 'SwordLv1', -1 , None, None)
    sword_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'SwordLv1'},
    {0: sword_get, 1: 'Event0'})
    
    shield_get = item_get.insertItemGetAnimation(flowchart, 'Shield', -1, None, None)
    shield_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Shield'},
    {0: shield_get, 1: sword_check})

    bracelet_get = item_get.insertItemGetAnimation(flowchart, 'PowerBraceletLv1', -1, None, None)
    bracelet_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'PowerBraceletLv1'},
    {0: bracelet_get, 1: shield_check})

    powder_capacity_get = item_get.insertItemGetAnimation(flowchart, 'MagicPowder_MaxUp', -1, None, None)
    powder_capacity_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'MagicPowder_MaxUp'},
    {0: powder_capacity_get, 1: bracelet_check})

    bomb_capacity_get = item_get.insertItemGetAnimation(flowchart, 'Bomb_MaxUp', -1, None, None)
    bomb_capacity_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Bomb_MaxUp'},
    {0: bomb_capacity_get, 1: powder_capacity_check})

    arrow_capacity_get = item_get.insertItemGetAnimation(flowchart, 'Arrow_MaxUp', -1, None, None)
    arrow_capacity_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Arrow_MaxUp'},
    {0: arrow_capacity_get, 1: bomb_capacity_check})

    red_tunic_get = item_get.insertItemGetAnimation(flowchart, 'ClothesRed', -1, None, None)
    red_tunic_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'ClothesRed'},
    {0: red_tunic_get, 1: arrow_capacity_check})

    blue_tunic_get = item_get.insertItemGetAnimation(flowchart, 'ClothesBlue', -1, None, None)
    blue_tunic_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'ClothesBlue'},
    {0: blue_tunic_get, 1: red_tunic_check})

    harp_get = item_get.insertItemGetAnimation(flowchart, 'SurfHarp', -1, None, None)
    harp_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'SurfHarp'},
    {0: harp_get, 1: blue_tunic_check})

    yoshi_get = item_get.insertItemGetAnimation(flowchart, 'YoshiDoll', -1, None, None)
    yoshi_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'YoshiDoll'},
    {0: yoshi_get, 1: harp_check})

    ribbon_get = item_get.insertItemGetAnimation(flowchart, 'Ribbon', -1, None, None)
    ribbon_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Ribbon'},
    {0: ribbon_get, 1: yoshi_check})

    dog_food_get = item_get.insertItemGetAnimation(flowchart, 'DogFood', -1, None, None)
    dog_food_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'DogFood'},
    {0: dog_food_get, 1: ribbon_check})

    bananas_get = item_get.insertItemGetAnimation(flowchart, 'Bananas', -1, None, None)
    bananas_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Bananas'},
    {0: bananas_get, 1: dog_food_check})

    stick_get = item_get.insertItemGetAnimation(flowchart, 'Stick', -1, None, None)
    stick_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Stick'},
    {0: stick_get, 1: bananas_check})

    honeycomb_get = item_get.insertItemGetAnimation(flowchart, 'Honeycomb', -1, None, None)
    honeycomb_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Honeycomb'},
    {0: honeycomb_get, 1: stick_check})

    pineapple_get = item_get.insertItemGetAnimation(flowchart, 'Pineapple', -1, None, None)
    pineapple_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Pineapple'},
    {0: pineapple_get, 1: honeycomb_check})

    hibiscus_get = item_get.insertItemGetAnimation(flowchart, 'Hibiscus', -1, None, None)
    hibiscus_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Hibiscus'},
    {0: hibiscus_get, 1: pineapple_check})

    letter_get = item_get.insertItemGetAnimation(flowchart, 'Letter', -1, None, None)
    letter_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Letter'},
    {0: letter_get, 1: hibiscus_check})

    broom_get = item_get.insertItemGetAnimation(flowchart, 'Broom', -1, None, None)
    broom_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Broom'},
    {0: broom_get, 1: letter_check})

    hook_get = item_get.insertItemGetAnimation(flowchart, 'FishingHook', -1, None, None)
    hook_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'FishingHook'},
    {0: hook_get, 1: broom_check})

    necklace_get = item_get.insertItemGetAnimation(flowchart, 'PinkBra', -1, None, None)
    necklace_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'PinkBra'},
    {0: necklace_get, 1: hook_check})

    scale_get = item_get.insertItemGetAnimation(flowchart, 'MermaidsScale', -1, None, None)
    scale_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'MermaidsScale'},
    {0: scale_get, 1: necklace_check})

    zap_get = item_get.insertItemGetAnimation(flowchart, 'ZapTrap', -1, None, None)
    zap_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'ZapTrap'},
    {0: zap_get, 1: scale_check})
    
    bomb_get = item_get.insertItemGetAnimation(flowchart, 'Bomb', -1, None, None)
    bomb_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'Bomb'},
    {0: bomb_get, 1: zap_check})

    medicine_get = item_get.insertItemGetAnimation(flowchart, 'SecretMedicine', -1, None, None)
    medicine_check = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString',
    {'value1': event_tools.findEvent(flowchart, 'Event0').data.params.data['itemKey'], 'value2': 'SecretMedicine'},
    {0: medicine_get, 1: bomb_check})

    event_tools.insertEventAfter(flowchart, 'Event4', medicine_check)
