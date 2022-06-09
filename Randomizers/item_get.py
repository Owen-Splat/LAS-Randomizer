import Tools.event_tools as event_tools
from data import SWORD_FOUND_FLAG, SHIELD_FOUND_FLAG, BRACELET_FOUND_FLAG, RED_TUNIC_FOUND_FLAG, BLUE_TUNIC_FOUND_FLAG



# Inserts an AddItemByKey and a GenericItemGetSequenceByKey, or a progressive item switch (depending on the item).
# It goes after 'before' and before 'after'. Return the name of the first event in the sequence.
def insert_item_get_animation(flowchart, item, index, before=None, after=None):
    if item == 'PowerBraceletLv1':
        return event_tools.createProgressiveItemSwitch(flowchart, 'PowerBraceletLv1', 'PowerBraceletLv2', BRACELET_FOUND_FLAG, before, after)

    if item == 'SwordLv1':
        spinAnim = event_tools.createActionChain(flowchart, before, [
            ('Link', 'RequestSwordRolling', {}),
            ('Link', 'PlayAnimationEx', {'blendTime': 0.1, 'name': 'slash_hold_lp', 'time': 0.8})
        ], after)
        return event_tools.createProgressiveItemSwitch(flowchart, 'SwordLv1', 'SwordLv2', SWORD_FOUND_FLAG, before, spinAnim)

    if item == 'Shield':
        return event_tools.createProgressiveItemSwitch(flowchart, 'Shield', 'MirrorShield', SHIELD_FOUND_FLAG, before, after)

    if item == 'MagicPowder_MaxUp':
        return event_tools.createActionChain(flowchart, before, [
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Inventory', 'AddItemByKey', {'itemKey': 'MagicPowder', 'count': 40, 'index': -1, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder', 'keepCarry': False, 'messageEntry': 'MagicPowder_MaxUp'})
            ], after)

    if item == 'Bomb_MaxUp':
        return event_tools.createActionChain(flowchart, before, [
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Inventory', 'AddItemByKey', {'itemKey': 'Bomb', 'count': 60, 'index': -1, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'Bomb', 'keepCarry': False, 'messageEntry': 'Bomb_MaxUp'})
            ], after)

    if item == 'Arrow_MaxUp':
        return event_tools.createActionChain(flowchart, before, [
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Inventory', 'AddItemByKey', {'itemKey': 'Arrow', 'count': 60, 'index': -1, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'Arrow', 'keepCarry': False, 'messageEntry': 'Arrow_MaxUp'})
            ], after)
    
    if item == 'SurfHarp':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': 'GhostClear1', 'value': True}), # set flags before giving harp, otherwise ghost requirements may be met during the itemget animation, leaving the player with a ghost that can only be rid of by getting another follower
            ('EventFlags', 'SetFlag', {'symbol': 'Ghost2_Clear', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'Ghost3_Clear', 'value': True}),
            ('EventFlags', 'SetFlag', {'symbol': 'Ghost4_Clear', 'value': True}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)

    if item == 'ClothesRed':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': RED_TUNIC_FOUND_FLAG, 'value': True}),
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Red_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder_MaxUp', 'keepCarry': False, 'messageEntry': 'ClothesRed'})
        ], after)
    
    if item == 'ClothesBlue':
        return event_tools.createActionChain(flowchart, before, [
            ('EventFlags', 'SetFlag', {'symbol': BLUE_TUNIC_FOUND_FLAG, 'value': True}),
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Blue_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder_MaxUp', 'keepCarry': False, 'messageEntry': 'ClothesBlue'})
        ], after)
    
    if item == 'ClothesGreen':
        return event_tools.createActionChain(flowchart, before, [
            ('Link', 'PlayTailorOtherChannelEx', {'channel': 'Change_Color_Green_00', 'index': 0, 'restart': False, 'time': 3.58}),
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': 'MagicPowder_MaxUp', 'keepCarry': False, 'messageEntry': 'ClothesGreen'})
        ], after)
    
    if item == 'SecretMedicine':
        return event_tools.createActionChain(flowchart, before, [
            ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
            ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''}),
            ('Link', 'Heal', {'amount': 99})
    ], after)

    return event_tools.createActionChain(flowchart, before, [
        ('Inventory', 'AddItemByKey', {'itemKey': item, 'count': 1, 'index': index, 'autoEquip': False}),
        ('Link', 'GenericItemGetSequenceByKey', {'itemKey': item, 'keepCarry': False, 'messageEntry': ''})
        ], after)
