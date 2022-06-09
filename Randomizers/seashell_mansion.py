import Tools.event_tools as event_tools
from Randomizers.data import SWORD_FOUND_FLAG, SHIELD_FOUND_FLAG, BRACELET_FOUND_FLAG



def change_rewards(flow, treasureBoxFlow, powderCapacity, bombCapacity, arrowCapacity, redTunic, blueTunic, harp):
    spinAnim = event_tools.createActionChain(flow.flowchart, None, [
        ('Link', 'RequestSwordRolling', {}),
        ('Link', 'PlayAnimationEx', {'blendTime': 0.1, 'name': 'slash_hold_lp', 'time': 0.8})
    ], 'Event0')

    swordFlagCheckEvent = event_tools.createProgressiveItemSwitch(flow.flowchart, 'SwordLv1', 'SwordLv2', SWORD_FOUND_FLAG, None, spinAnim)
    swordContentCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'SwordLv1'}, {0: swordFlagCheckEvent, 1: 'Event3'})
    
    shieldFlagCheckEvent = event_tools.createProgressiveItemSwitch(flow.flowchart, 'Shield', 'MirrorShield', SHIELD_FOUND_FLAG, None, 'Event0')
    shieldContentCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Shield'}, {0: shieldFlagCheckEvent, 1: swordContentCheckEvent})

    braceletFlagCheckEvent = event_tools.createProgressiveItemSwitch(flow.flowchart, 'PowerBraceletLv1', 'PowerBraceletLv2', BRACELET_FOUND_FLAG, None, 'Event0')
    braceletContentCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'PowerBraceletLv1'}, {0: braceletFlagCheckEvent, 1: shieldContentCheckEvent})

    powderCapacityCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'MagicPowder_MaxUp'}, {0: powderCapacity, 1: braceletContentCheckEvent})
    bombCapacityCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Bomb_MaxUp'}, {0: bombCapacity, 1: powderCapacityCheckEvent})
    arrowCapacityCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'Arrow_MaxUp'}, {0: arrowCapacity, 1: bombCapacityCheckEvent})
    redTunicCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'ClothesRed'}, {0: redTunic, 1: arrowCapacityCheckEvent})
    blueTunicCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'ClothesBlue'}, {0: blueTunic, 1: redTunicCheckEvent})
    harpCheckEvent = event_tools.createSwitchEvent(flow.flowchart, 'FlowControl', 'CompareString', {'value1': event_tools.findEvent(treasureBoxFlow.flowchart, 'Event33').data.params.data['value1'], 'value2': 'SurfHarp'}, {0: harp, 1: blueTunicCheckEvent})

    event_tools.insertEventAfter(flow.flowchart, 'Event3', 'Event4')
    event_tools.insertEventAfter(flow.flowchart, 'Event4', 'Event14')
    event_tools.insertEventAfter(flow.flowchart, 'Event14', 'Event0')
    event_tools.insertEventAfter(flow.flowchart, 'Event25', harpCheckEvent)



def make_event_changes(flow, placements):
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

