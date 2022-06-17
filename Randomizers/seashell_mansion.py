import Tools.event_tools as event_tools
from Randomizers.data import SWORD_FOUND_FLAG, SHIELD_FOUND_FLAG, BRACELET_FOUND_FLAG
import Randomizers.item_get as item_get



def changeRewards(flow, treasureBoxFlow):
    spinAnim = event_tools.createActionChain(flow.flowchart, None, [
        ('Link', 'RequestSwordRolling', {}),
        ('Link', 'PlayAnimationEx', {'blendTime': 0.1, 'name': 'slash_hold_lp', 'time': 0.8})
    ], 'Event0')

    swordFlagCheck = event_tools.createProgressiveItemSwitch(flow.flowchart, 'SwordLv1', 'SwordLv2', SWORD_FOUND_FLAG, None, spinAnim)
    swordContentCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'SwordLv1'}, {0: swordFlagCheck, 1: 'Event3'})
    
    shieldFlagCheck = event_tools.createProgressiveItemSwitch(flow.flowchart, 'Shield', 'MirrorShield', SHIELD_FOUND_FLAG, None, 'Event0')
    shieldContentCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Shield'}, {0: shieldFlagCheck, 1: swordContentCheck})

    braceletFlagCheck = event_tools.createProgressiveItemSwitch(flow.flowchart, 'PowerBraceletLv1', 'PowerBraceletLv2', BRACELET_FOUND_FLAG, None, 'Event0')
    braceletContentCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'PowerBraceletLv1'}, {0: braceletFlagCheck, 1: shieldContentCheck})

    powderCapacityGet = item_get.insertItemGetAnimation(flow.flowchart, 'MagicPowder_MaxUp', -1, None, 'Event0')
    powderCapacityCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'MagicPowder_MaxUp'}, {0: powderCapacityGet, 1: braceletContentCheck})

    bombCapacityGet = item_get.insertItemGetAnimation(flow.flowchart, 'Bomb_MaxUp', -1, None, 'Event0')
    bombCapacityCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Bomb_MaxUp'}, {0: bombCapacityGet, 1: powderCapacityCheck})

    arrowCapacityGet = item_get.insertItemGetAnimation(flow.flowchart, 'Arrow_MaxUp', -1, None, 'Event0')
    arrowCapacityCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Arrow_MaxUp'}, {0: arrowCapacityGet, 1: bombCapacityCheck})

    redTunicGet = item_get.insertItemGetAnimation(flow.flowchart, 'ClothesRed', -1, None, 'Event0')
    redTunicCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'ClothesRed'}, {0: redTunicGet, 1: arrowCapacityCheck})

    blueTunicGet = item_get.insertItemGetAnimation(flow.flowchart, 'ClothesBlue', -1, None, 'Event0')
    blueTunicCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'ClothesBlue'}, {0: blueTunicGet, 1: redTunicCheck})

    harpGet = item_get.insertItemGetAnimation(flow.flowchart, 'SurfHarp', -1, None, 'Event0')
    harpCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'SurfHarp'}, {0: harpGet, 1: blueTunicCheck})

    yoshiGet = item_get.insertItemGetAnimation(flow.flowchart, 'YoshiDoll', -1, None, 'Event0')
    yoshiCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'YoshiDoll'}, {0: yoshiGet, 1: harpCheck})

    ribbonGet = item_get.insertItemGetAnimation(flow.flowchart, 'Ribbon', -1, None, 'Event0')
    ribbonCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Ribbon'}, {0: ribbonGet, 1: yoshiCheck})

    dogFoodGet = item_get.insertItemGetAnimation(flow.flowchart, 'DogFood', -1, None, 'Event0')
    dogFoodCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'DogFood'}, {0: dogFoodGet, 1: ribbonCheck})

    bananasGet = item_get.insertItemGetAnimation(flow.flowchart, 'Bananas', -1, None, 'Event0')
    bananasCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Bananas'}, {0: bananasGet, 1: dogFoodCheck})

    stickGet = item_get.insertItemGetAnimation(flow.flowchart, 'Stick', -1, None, 'Event0')
    stickCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Stick'}, {0: stickGet, 1: bananasCheck})

    honeycombGet = item_get.insertItemGetAnimation(flow.flowchart, 'Honeycomb', -1, None, 'Event0')
    honeycombCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Honeycomb'}, {0: honeycombGet, 1: stickCheck})

    pineappleGet = item_get.insertItemGetAnimation(flow.flowchart, 'Pineapple', -1, None, 'Event0')
    pineappleCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Pineapple'}, {0: pineappleGet, 1: honeycombCheck})

    hibiscusGet = item_get.insertItemGetAnimation(flow.flowchart, 'Hibiscus', -1, None, 'Event0')
    hibiscusCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Hibiscus'}, {0: hibiscusGet, 1: pineappleCheck})

    letterGet = item_get.insertItemGetAnimation(flow.flowchart, 'Letter', -1, None, 'Event0')
    letterCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Letter'}, {0: letterGet, 1: hibiscusCheck})

    broomGet = item_get.insertItemGetAnimation(flow.flowchart, 'Broom', -1, None, 'Event0')
    broomCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Broom'}, {0: broomGet, 1: letterCheck})

    hookGet = item_get.insertItemGetAnimation(flow.flowchart, 'FishingHook', -1, None, 'Event0')
    hookCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'FishingHook'}, {0: hookGet, 1: broomCheck})

    necklaceGet = item_get.insertItemGetAnimation(flow.flowchart, 'PinkBra', -1, None, 'Event0')
    necklaceCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'PinkBra'}, {0: necklaceGet, 1: hookCheck})

    scaleGet = item_get.insertItemGetAnimation(flow.flowchart, 'MermaidsScale', -1, None, 'Event0')
    scaleCheck = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'MermaidsScale'}, {0: scaleGet, 1: necklaceCheck})

    event_tools.insertEventAfter(flow.flowchart, 'Event3', 'Event4')
    event_tools.insertEventAfter(flow.flowchart, 'Event4', 'Event14')
    event_tools.insertEventAfter(flow.flowchart, 'Event14', 'Event0')
    event_tools.insertEventAfter(flow.flowchart, 'Event25', scaleCheck)



def makeEventChanges(flow, placements):
    # 40 shells, doesn't use a present box
    event_tools.findEvent(flow.flowchart, 'Event65').data.forks.pop(0)

    event_tools.insertEventAfter(flow.flowchart, 'Event64', 'Event65')

    # Remove the thing to show Link's sword because it will show L1 sword if he has none. 
    swordCheck1 = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': SWORD_FOUND_FLAG}, {0: 'Event65', 1: 'Event64'})
    event_tools.insertEventAfter(flow.flowchart, 'Event80', swordCheck1)

    # However, leave it the 2nd time if he's going to get one here.
    if placements['40-seashell-reward'] != 'sword':
        swordCheck2 = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': SWORD_FOUND_FLAG}, {0: 'Event48', 1: 'Event47'})
        event_tools.insertEventAfter(flow.flowchart, 'Event54', swordCheck2)
    
    # Special case, if there is a sword here, then actually give them item before the end of the animation so it looks like the vanilla cutscene :)
    if placements['40-seashell-reward'] == 'sword':
        earlyGiveSword1 = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv1', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
        earlyGiveSword2 = event_tools.createActionEvent(flow.flowchart, 'Inventory', 'AddItemByKey', {'itemKey': 'SwordLv2', 'count': 1, 'index': -1, 'autoEquip': False}, 'Event19')
        swordCheck3 = event_tools.createSwitchEvent(flow.flowchart, 'EventFlags', 'CheckFlag', {'symbol': SWORD_FOUND_FLAG}, {0: earlyGiveSword1, 1: earlyGiveSword2})
        event_tools.insertEventAfter(flow.flowchart, 'Event74', swordCheck3)
    else:
        event_tools.insertEventAfter(flow.flowchart, 'Event74', 'Event19')

