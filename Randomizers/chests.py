import Tools.event_tools as event_tools
from Randomizers import item_get, data



def writeChestEvent(flowchart):
    """Writes an itemKey comparision and itemGet chain and connects it to the chest open events"""

    swordGet = item_get.insertItemGetAnimation(flowchart, 'SwordLv1', -1 , None, None)
    swordContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'SwordLv1'}, {0: swordGet, 1: 'Event33'})
    
    shieldGet = item_get.insertItemGetAnimation(flowchart, 'Shield', -1, None, None)
    shieldContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'Shield'}, {0: shieldGet, 1: swordContentCheck})

    braceletGet = item_get.insertItemGetAnimation(flowchart, 'PowerBraceletLv1', -1, None, None)
    braceletContentCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'PowerBraceletLv1'}, {0: braceletGet, 1: shieldContentCheck})

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

    boxClose = event_tools.createSubFlowEvent(flowchart, '', 'BoxClose', {}, None)
    medicineGet = event_tools.createActionChain(flowchart, None, [
        ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'SecretMedicine', 'keeyCarry': False, 'messageEntry': 'SecretMedicine2'}),
        ('Link', 'Heal', {'amount': 99}),
        ('TreasureBox', 'SetActorSwitch', {'switchIndex': 1, 'value': False})
    ], boxClose)
    medicineCheck = event_tools.createSwitchEvent(flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(flowchart, 'Event33').data.params.data['value1'], 'value2': 'SecretMedicine'}, {0: medicineGet, 1: bombCheck})

    event_tools.insertEventAfter(flowchart, 'Event32', medicineCheck)
    event_tools.insertEventAfter(flowchart, 'Event28', medicineCheck) # add this chain to TreasureBox_ShockOpen for the D6 Pot Chest
