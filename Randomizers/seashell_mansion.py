import Tools.event_tools as event_tools
from Randomizers import item_get
from Randomizers import data



def changeRewards(flowchart, treasureBoxFlow):
    """Adds a itemKey comparison and itemGet animation chain to when you open presents"""
    
    swordGet = item_get.insertItemGetAnimation(flowchart, 'SwordLv1', -1 , None, 'Event0')
    swordContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'SwordLv1'}, {0: swordGet, 1: 'Event3'})
    
    shieldGet = item_get.insertItemGetAnimation(flowchart, 'Shield', -1, None, 'Event0')
    shieldContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Shield'}, {0: shieldGet, 1: swordContentCheck})

    braceletGet = item_get.insertItemGetAnimation(flowchart, 'PowerBraceletLv1', -1, None, 'Event0')
    braceletContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'PowerBraceletLv1'}, {0: braceletGet, 1: shieldContentCheck})

    powderCapacityGet = item_get.insertItemGetAnimation(flowchart, 'MagicPowder_MaxUp', -1, None, 'Event0')
    powderCapacityCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'MagicPowder_MaxUp'}, {0: powderCapacityGet, 1: braceletContentCheck})

    bombCapacityGet = item_get.insertItemGetAnimation(flowchart, 'Bomb_MaxUp', -1, None, 'Event0')
    bombCapacityCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Bomb_MaxUp'}, {0: bombCapacityGet, 1: powderCapacityCheck})

    arrowCapacityGet = item_get.insertItemGetAnimation(flowchart, 'Arrow_MaxUp', -1, None, 'Event0')
    arrowCapacityCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Arrow_MaxUp'}, {0: arrowCapacityGet, 1: bombCapacityCheck})

    redTunicGet = item_get.insertItemGetAnimation(flowchart, 'ClothesRed', -1, None, 'Event0')
    redTunicCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'ClothesRed'}, {0: redTunicGet, 1: arrowCapacityCheck})

    blueTunicGet = item_get.insertItemGetAnimation(flowchart, 'ClothesBlue', -1, None, 'Event0')
    blueTunicCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'ClothesBlue'}, {0: blueTunicGet, 1: redTunicCheck})

    harpGet = item_get.insertItemGetAnimation(flowchart, 'SurfHarp', -1, None, 'Event0')
    harpCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'SurfHarp'}, {0: harpGet, 1: blueTunicCheck})

    yoshiGet = item_get.insertItemGetAnimation(flowchart, 'YoshiDoll', -1, None, 'Event0')
    yoshiCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'YoshiDoll'}, {0: yoshiGet, 1: harpCheck})

    ribbonGet = item_get.insertItemGetAnimation(flowchart, 'Ribbon', -1, None, 'Event0')
    ribbonCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Ribbon'}, {0: ribbonGet, 1: yoshiCheck})

    dogFoodGet = item_get.insertItemGetAnimation(flowchart, 'DogFood', -1, None, 'Event0')
    dogFoodCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'DogFood'}, {0: dogFoodGet, 1: ribbonCheck})

    bananasGet = item_get.insertItemGetAnimation(flowchart, 'Bananas', -1, None, 'Event0')
    bananasCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Bananas'}, {0: bananasGet, 1: dogFoodCheck})

    stickGet = item_get.insertItemGetAnimation(flowchart, 'Stick', -1, None, 'Event0')
    stickCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Stick'}, {0: stickGet, 1: bananasCheck})

    honeycombGet = item_get.insertItemGetAnimation(flowchart, 'Honeycomb', -1, None, 'Event0')
    honeycombCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Honeycomb'}, {0: honeycombGet, 1: stickCheck})

    pineappleGet = item_get.insertItemGetAnimation(flowchart, 'Pineapple', -1, None, 'Event0')
    pineappleCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Pineapple'}, {0: pineappleGet, 1: honeycombCheck})

    hibiscusGet = item_get.insertItemGetAnimation(flowchart, 'Hibiscus', -1, None, 'Event0')
    hibiscusCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Hibiscus'}, {0: hibiscusGet, 1: pineappleCheck})

    letterGet = item_get.insertItemGetAnimation(flowchart, 'Letter', -1, None, 'Event0')
    letterCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Letter'}, {0: letterGet, 1: hibiscusCheck})

    broomGet = item_get.insertItemGetAnimation(flowchart, 'Broom', -1, None, 'Event0')
    broomCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Broom'}, {0: broomGet, 1: letterCheck})

    hookGet = item_get.insertItemGetAnimation(flowchart, 'FishingHook', -1, None, 'Event0')
    hookCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'FishingHook'}, {0: hookGet, 1: broomCheck})

    necklaceGet = item_get.insertItemGetAnimation(flowchart, 'PinkBra', -1, None, 'Event0')
    necklaceCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'PinkBra'}, {0: necklaceGet, 1: hookCheck})

    scaleGet = item_get.insertItemGetAnimation(flowchart, 'MermaidsScale', -1, None, 'Event0')
    scaleCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'MermaidsScale'}, {0: scaleGet, 1: necklaceCheck})

    zapGet = item_get.insertItemGetAnimation(flowchart, 'ZapTrap', -1, None, 'Event0')
    zapCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'ZapTrap'}, {0: zapGet, 1: scaleCheck})
    
    bombGet = item_get.insertItemGetAnimation(flowchart, 'Bomb', -1, None, 'Event0')
    bombCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Bomb'}, {0: bombGet, 1: zapCheck})

    event_tools.insertEventAfter(flowchart, 'Event3', 'Event4')
    event_tools.insertEventAfter(flowchart, 'Event4', 'Event14')
    event_tools.insertEventAfter(flowchart, 'Event14', 'Event0')
    event_tools.insertEventAfter(flowchart, 'Event25', bombCheck)



def makeEventChanges(flowchart, placements):
    # 40 shells, doesn't use a present box
    event_tools.findEvent(flowchart, 'Event65').data.forks.pop(0)

    event_tools.insertEventAfter(flowchart, 'Event64', 'Event65')

    # Remove the thing to show Link's sword because it will show L1 sword if he has none. 
    swordCheck1 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag', {'symbol': data.SWORD_FOUND_FLAG}, {0: 'Event65', 1: 'Event64'})
    event_tools.insertEventAfter(flowchart, 'Event80', swordCheck1)

    # However, leave it the 2nd time if he's going to get one here.
    if placements['40-seashell-reward'] != 'sword':
        swordCheck2 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag', {'symbol': data.SWORD_FOUND_FLAG}, {0: 'Event48', 1: 'Event47'})
        event_tools.insertEventAfter(flowchart, 'Event54', swordCheck2)
    
    # Special case, if there is a sword here, then actually give them item before the end of the animation so it looks like the vanilla cutscene :)
    if placements['40-seashell-reward'] == 'sword':
        earlyGiveSword1 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv1', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
        earlyGiveSword2 = event_tools.createActionEvent(flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv2', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
        swordCheck3 = event_tools.createSwitchEvent(flowchart, 'EventFlags', 'CheckFlag', {'symbol': data.SWORD_FOUND_FLAG}, {0: earlyGiveSword1, 1: earlyGiveSword2})
        event_tools.insertEventAfter(flowchart, 'Event74', swordCheck3)
    else:
        event_tools.insertEventAfter(flowchart, 'Event74', 'Event19')

