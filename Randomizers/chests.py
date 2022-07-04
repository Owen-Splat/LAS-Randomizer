import Tools.event_tools as event_tools
from Randomizers import item_get, data



def writeChestEvent(flowchart):
    spinAnim = event_tools.createActionChain(flowchart, None, [
        ('Link', 'RequestSwordRolling', {}),
        ('Link', 'PlayAnimationEx', {'blendTime': 0.1, 'name': 'slash_hold_lp', 'time': 0.8})
    ])

    swordFlagCheck = event_tools.createProgressiveItemSwitch(flowchart, 'SwordLv1', 'SwordLv2', data.SWORD_FOUND_FLAG, None, spinAnim)
    swordContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'SwordLv1'}, {0: swordFlagCheck, 1: 'Event33'})
    
    shieldFlagCheck = event_tools.createProgressiveItemSwitch(flowchart, 'Shield', 'MirrorShield', data.SHIELD_FOUND_FLAG, None, None)
    shieldContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Shield'}, {0: shieldFlagCheck, 1: swordContentCheck})

    braceletFlagCheck = event_tools.createProgressiveItemSwitch(flowchart, 'PowerBraceletLv1', 'PowerBraceletLv2', data.BRACELET_FOUND_FLAG, None, None)
    braceletContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'PowerBraceletLv1'}, {0: braceletFlagCheck, 1: shieldContentCheck})

    powderCapacityGet = item_get.insertItemGetAnimation(flowchart, 'MagicPowder_MaxUp', -1, None, None)
    powderCapacityCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'MagicPowder_MaxUp'}, {0: powderCapacityGet, 1: braceletContentCheck})

    bombCapacityGet = item_get.insertItemGetAnimation(flowchart, 'Bomb_MaxUp', -1, None, None)
    bombCapacityCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Bomb_MaxUp'}, {0: bombCapacityGet, 1: powderCapacityCheck})

    arrowCapacityGet = item_get.insertItemGetAnimation(flowchart, 'Arrow_MaxUp', -1, None, None)
    arrowCapacityCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Arrow_MaxUp'}, {0: arrowCapacityGet, 1: bombCapacityCheck})

    redTunicGet = item_get.insertItemGetAnimation(flowchart, 'ClothesRed', -1, None, None)
    redTunicCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'ClothesRed'}, {0: redTunicGet, 1: arrowCapacityCheck})

    blueTunicGet = item_get.insertItemGetAnimation(flowchart, 'ClothesBlue', -1, None, None)
    blueTunicCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'ClothesBlue'}, {0: blueTunicGet, 1: redTunicCheck})

    harpGet = item_get.insertItemGetAnimation(flowchart, 'SurfHarp', -1, None, None)
    harpCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'SurfHarp'}, {0: harpGet, 1: blueTunicCheck})

    yoshiGet = item_get.insertItemGetAnimation(flowchart, 'YoshiDoll', -1, None, None)
    yoshiCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'YoshiDoll'}, {0: yoshiGet, 1: harpCheck})

    ribbonGet = item_get.insertItemGetAnimation(flowchart, 'Ribbon', -1, None, None)
    ribbonCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Ribbon'}, {0: ribbonGet, 1: yoshiCheck})

    dogFoodGet = item_get.insertItemGetAnimation(flowchart, 'DogFood', -1, None, None)
    dogFoodCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'DogFood'}, {0: dogFoodGet, 1: ribbonCheck})

    bananasGet = item_get.insertItemGetAnimation(flowchart, 'Bananas', -1, None, None)
    bananasCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Bananas'}, {0: bananasGet, 1: dogFoodCheck})

    stickGet = item_get.insertItemGetAnimation(flowchart, 'Stick', -1, None, None)
    stickCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Stick'}, {0: stickGet, 1: bananasCheck})

    honeycombGet = item_get.insertItemGetAnimation(flowchart, 'Honeycomb', -1, None, None)
    honeycombCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Honeycomb'}, {0: honeycombGet, 1: stickCheck})

    pineappleGet = item_get.insertItemGetAnimation(flowchart, 'Pineapple', -1, None, None)
    pineappleCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Pineapple'}, {0: pineappleGet, 1: honeycombCheck})

    hibiscusGet = item_get.insertItemGetAnimation(flowchart, 'Hibiscus', -1, None, None)
    hibiscusCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Hibiscus'}, {0: hibiscusGet, 1: pineappleCheck})

    letterGet = item_get.insertItemGetAnimation(flowchart, 'Letter', -1, None, None)
    letterCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Letter'}, {0: letterGet, 1: hibiscusCheck})

    broomGet = item_get.insertItemGetAnimation(flowchart, 'Broom', -1, None, None)
    broomCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Broom'}, {0: broomGet, 1: letterCheck})

    hookGet = item_get.insertItemGetAnimation(flowchart, 'FishingHook', -1, None, None)
    hookCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'FishingHook'}, {0: hookGet, 1: broomCheck})

    necklaceGet = item_get.insertItemGetAnimation(flowchart, 'PinkBra', -1, None, None)
    necklaceCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'PinkBra'}, {0: necklaceGet, 1: hookCheck})

    scaleGet = item_get.insertItemGetAnimation(flowchart, 'MermaidsScale', -1, None, None)
    scaleCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'MermaidsScale'}, {0: scaleGet, 1: necklaceCheck})

    zapGet = item_get.insertItemGetAnimation(flowchart, 'ZapTrap', -1, None, None)
    zapCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'ZapTrap'}, {0: zapGet, 1: scaleCheck})
    
    bombGet = item_get.insertItemGetAnimation(flowchart, 'Bomb', -1, None, None)
    bombCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Bomb'}, {0: bombGet, 1: zapCheck})

    event_tools.insertEventAfter(flowchart, 'Event32', bombCheck)
