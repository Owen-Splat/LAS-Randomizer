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
